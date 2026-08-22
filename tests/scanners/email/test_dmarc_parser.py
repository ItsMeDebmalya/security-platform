"""DMARC parsing, per RFC 7489."""

from __future__ import annotations

import pytest

from scanners.email.dmarc import parse_dmarc


def test_a_minimal_record_parses():
    record = parse_dmarc("v=DMARC1; p=reject")

    assert record.valid
    assert record.policy == "reject"


def test_whitespace_around_tags_is_ignored():
    assert parse_dmarc("v=DMARC1 ;  p = reject ;").valid


def test_the_version_tag_must_come_first():
    """RFC 7489 6.3: v must be the first tag, and p must immediately follow it."""
    record = parse_dmarc("p=reject; v=DMARC1")

    assert not record.valid


def test_a_record_without_the_version_tag_is_not_a_dmarc_record():
    assert not parse_dmarc("p=reject").valid


def test_a_record_without_a_policy_is_invalid():
    """RFC 7489: p is required; without it the record is ignored entirely."""
    record = parse_dmarc("v=DMARC1; rua=mailto:d@example.com")

    assert not record.valid
    assert "p=" in record.errors[0]


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
def test_every_defined_policy_is_accepted(policy):
    assert parse_dmarc(f"v=DMARC1; p={policy}").policy == policy


def test_an_undefined_policy_is_invalid():
    assert not parse_dmarc("v=DMARC1; p=destroy").valid


def test_the_policy_is_case_insensitive():
    assert parse_dmarc("v=DMARC1; p=REJECT").policy == "reject"


# --- the optional tags ------------------------------------------------------


def test_the_subdomain_policy_is_read():
    assert parse_dmarc("v=DMARC1; p=reject; sp=none").subdomain_policy == "none"


def test_the_subdomain_policy_defaults_to_the_domain_policy():
    """RFC 7489: sp defaults to p."""
    assert parse_dmarc("v=DMARC1; p=quarantine").effective_subdomain_policy == "quarantine"


def test_pct_defaults_to_one_hundred():
    assert parse_dmarc("v=DMARC1; p=reject").pct == 100


def test_a_partial_pct_is_read():
    assert parse_dmarc("v=DMARC1; p=reject; pct=20").pct == 20


def test_a_pct_outside_the_range_is_invalid():
    assert not parse_dmarc("v=DMARC1; p=reject; pct=200").valid


def test_a_non_numeric_pct_is_invalid():
    assert not parse_dmarc("v=DMARC1; p=reject; pct=lots").valid


def test_alignment_defaults_to_relaxed():
    record = parse_dmarc("v=DMARC1; p=reject")

    assert (record.adkim, record.aspf) == ("r", "r")


def test_strict_alignment_is_read():
    record = parse_dmarc("v=DMARC1; p=reject; adkim=s; aspf=s")

    assert (record.adkim, record.aspf) == ("s", "s")


def test_an_invalid_alignment_value_is_invalid():
    assert not parse_dmarc("v=DMARC1; p=reject; aspf=maybe").valid


def test_reporting_addresses_are_read():
    record = parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.com")

    assert record.rua == ["mailto:a@example.com", "mailto:b@example.com"]


def test_a_record_with_no_rua_reports_none():
    assert parse_dmarc("v=DMARC1; p=reject").rua == []


def test_an_unknown_tag_is_ignored_rather_than_fatal():
    """RFC 7489 6.3: unknown tags are ignored."""
    assert parse_dmarc("v=DMARC1; p=reject; futuretag=whatever").valid


def test_a_duplicate_tag_is_invalid():
    assert not parse_dmarc("v=DMARC1; p=reject; p=none").valid


def test_the_raw_record_and_parse_tree_are_kept_for_evidence():
    record = parse_dmarc("v=DMARC1; p=none; pct=50")

    assert record.to_dict()["raw"] == "v=DMARC1; p=none; pct=50"
    assert record.to_dict()["tags"]["pct"] == "50"
