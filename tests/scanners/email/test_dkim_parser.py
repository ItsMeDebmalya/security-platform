"""DKIM key record parsing, per RFC 6376.

Key strength is read out of the DER-encoded public key rather than trusted
from a tag, because there is no tag that states it.
"""

from __future__ import annotations

import pytest

from scanners.email.dkim import parse_dkim_key

RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxntLCj4ULaZcJl5J7HXYk0ANV4ZXEi2D6IZMpEhJ3"
    "H7ntz5ANAY/JQki9S6ZvTQB546YA1ShEXqc5f/r1HtJXQTi6lBkTIWYq1Go3e8vm+uWFT+Hjyv394AqB"
    "cEzch8jRI4zqiOwvW2PDQGxHesiUr7LU3xonJCBNP0oQk9CkcwIDAQAB"
)
RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzE6PIiHT/sKrAyfdiCc+a7kdmUWcniaPH9J"
    "hGYxO8vRORbkz/GQFZUNN0kogF3TDDqX9263KJe/yX5+/xoJFDBEOoBX9a8uuOA6BCNImyoHiQ6YWB9b"
    "LH0ciUhVHvGjZhH7BGbJMuE/y+eh2uw6APj+7qOpnAs6jyYvOr8LlHDVURaaptx8j9AJx8GHyTD1pzSI"
    "y6Cum9di5IL5/I8Ewx7eT5DJ4Z9Gu+8dQdCi431Qbwe0t+4OpdmsBpbDnj333VSUVlI7UIgdAubpCw4Z"
    "cqFDIy7vYmlPCrdOZ2J4bpPaLGNslkG+YjZ/X5NScgG/mcds+03QvWh4XrpVxNnHTQIDAQAB"
)


def test_a_minimal_key_record_parses():
    record = parse_dkim_key(f"v=DKIM1; k=rsa; p={RSA_2048}")

    assert record.valid
    assert record.key_type == "rsa"


def test_the_version_tag_is_optional():
    """RFC 6376 3.6.1: v is recommended, and defaults to DKIM1 when absent."""
    assert parse_dkim_key(f"k=rsa; p={RSA_2048}").valid


def test_the_key_type_defaults_to_rsa():
    assert parse_dkim_key(f"p={RSA_2048}").key_type == "rsa"


def test_a_wrong_version_is_invalid():
    assert not parse_dkim_key(f"v=DKIM2; p={RSA_2048}").valid


def test_a_record_with_no_p_tag_is_invalid():
    assert not parse_dkim_key("v=DKIM1; k=rsa").valid


def test_an_empty_p_tag_means_the_key_is_revoked():
    """RFC 6376: an empty p= revokes the key. That is deliberate, not broken."""
    record = parse_dkim_key("v=DKIM1; k=rsa; p=")

    assert record.revoked is True
    assert record.valid


def test_a_key_in_testing_mode_is_flagged():
    record = parse_dkim_key(f"v=DKIM1; k=rsa; p={RSA_2048}; t=y")

    assert record.testing is True


def test_a_key_not_in_testing_mode_says_so():
    assert parse_dkim_key(f"v=DKIM1; p={RSA_2048}").testing is False


# --- key strength -----------------------------------------------------------


def test_a_2048_bit_rsa_key_is_measured_as_2048():
    assert parse_dkim_key(f"v=DKIM1; k=rsa; p={RSA_2048}").key_bits == 2048


def test_a_1024_bit_rsa_key_is_measured_as_1024():
    assert parse_dkim_key(f"v=DKIM1; k=rsa; p={RSA_1024}").key_bits == 1024


def test_an_ed25519_key_reports_its_fixed_strength():
    record = parse_dkim_key("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")

    assert record.key_type == "ed25519"
    assert record.key_bits == 256


def test_a_key_that_is_not_valid_base64_is_invalid():
    record = parse_dkim_key("v=DKIM1; k=rsa; p=not!base64!")

    assert not record.valid


def test_a_key_that_is_not_a_valid_public_key_reports_unknown_strength():
    """Unknown is not zero: we say we could not measure it rather than guessing."""
    record = parse_dkim_key("v=DKIM1; k=rsa; p=aGVsbG8gd29ybGQ=")

    assert record.key_bits is None


@pytest.mark.parametrize("key_type", ["rsa", "ed25519"])
def test_the_key_type_is_case_insensitive(key_type):
    assert parse_dkim_key(f"v=DKIM1; k={key_type.upper()}; p={RSA_2048}").key_type == key_type


def test_the_parse_tree_is_available_as_evidence():
    record = parse_dkim_key(f"v=DKIM1; k=rsa; p={RSA_2048}")

    assert record.to_dict()["key_bits"] == 2048
    assert record.to_dict()["tags"]["k"] == "rsa"
