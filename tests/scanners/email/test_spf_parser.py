"""SPF parsing, per RFC 7208.

A real parser, not a regex: regexes get include: chains, macros and
qualifiers wrong, and the lookup-limit count is the check nobody else does.
"""

from __future__ import annotations

import pytest

from scanners.email.spf import DNS_LOOKUP_MECHANISMS, SpfRecord, parse_spf

# --- what an SPF record is --------------------------------------------------


def test_a_minimal_record_parses():
    record = parse_spf("v=spf1 -all")

    assert record.valid
    assert [t.mechanism for t in record.terms] == ["all"]


def test_the_version_tag_is_case_insensitive():
    assert parse_spf("V=SPF1 -all").valid


def test_a_record_without_the_version_tag_is_not_an_spf_record():
    record = parse_spf("include:_spf.example.net -all")

    assert not record.valid
    assert "v=spf1" in record.errors[0]


def test_an_empty_record_is_invalid():
    assert not parse_spf("").valid


def test_terms_are_separated_by_arbitrary_whitespace():
    record = parse_spf("v=spf1   ip4:192.0.2.0/24\tinclude:_spf.example.net  -all")

    assert len(record.terms) == 3


# --- qualifiers -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "qualifier"), [("+all", "+"), ("-all", "-"), ("~all", "~"), ("?all", "?")]
)
def test_every_qualifier_is_recognised(text, qualifier):
    record = parse_spf(f"v=spf1 {text}")

    assert record.terms[0].qualifier == qualifier


def test_a_mechanism_with_no_qualifier_defaults_to_pass():
    record = parse_spf("v=spf1 all")

    assert record.terms[0].qualifier == "+"


def test_the_all_qualifier_is_available_as_the_policy():
    assert parse_spf("v=spf1 ip4:192.0.2.1 ~all").all_qualifier == "~"


def test_a_record_with_no_all_mechanism_has_no_policy():
    assert parse_spf("v=spf1 ip4:192.0.2.1").all_qualifier is None


# --- mechanisms and modifiers ----------------------------------------------


def test_an_include_carries_the_domain_it_points_at():
    record = parse_spf("v=spf1 include:_spf.example.net -all")

    assert record.terms[0].mechanism == "include"
    assert record.terms[0].value == "_spf.example.net"


def test_a_redirect_modifier_is_recognised():
    record = parse_spf("v=spf1 redirect=_spf.example.net")

    assert record.redirect == "_spf.example.net"


def test_an_exp_modifier_is_recognised_and_costs_no_lookup():
    record = parse_spf("v=spf1 exp=explain.example.net -all")

    assert record.valid
    assert record.direct_lookup_count() == 0


def test_an_unknown_mechanism_makes_the_record_invalid():
    record = parse_spf("v=spf1 frobnicate:example.net -all")

    assert not record.valid


def test_an_unknown_modifier_is_ignored_rather_than_fatal():
    """RFC 7208 5.1: unrecognised modifiers are ignored."""
    record = parse_spf("v=spf1 futuretag=whatever -all")

    assert record.valid


def test_a_malformed_ip4_is_an_error():
    assert not parse_spf("v=spf1 ip4:999.0.2.0/24 -all").valid


def test_a_valid_ip4_cidr_parses():
    assert parse_spf("v=spf1 ip4:192.0.2.0/24 -all").valid


def test_a_valid_ip6_parses():
    assert parse_spf("v=spf1 ip6:2001:db8::/32 -all").valid


def test_two_redirect_modifiers_are_an_error():
    """RFC 7208 6: a modifier may appear at most once."""
    assert not parse_spf("v=spf1 redirect=a.example redirect=b.example").valid


def test_a_macro_in_a_mechanism_does_not_break_parsing():
    record = parse_spf("v=spf1 exists:%{i}._spf.example.net -all")

    assert record.valid
    assert record.terms[0].mechanism == "exists"


# --- the lookup limit -------------------------------------------------------


def test_the_mechanisms_that_cost_a_lookup_are_the_ones_the_rfc_names():
    assert frozenset({"include", "a", "mx", "ptr", "exists"}) == DNS_LOOKUP_MECHANISMS


def test_ip4_and_ip6_do_not_count_towards_the_limit():
    """Counting them is the classic bug that makes this check wrong."""
    record = parse_spf("v=spf1 " + " ".join(f"ip4:192.0.2.{i}" for i in range(20)) + " -all")

    assert record.direct_lookup_count() == 0


def test_all_does_not_count_towards_the_limit():
    assert parse_spf("v=spf1 -all").direct_lookup_count() == 0


def test_each_lookup_mechanism_counts_once():
    record = parse_spf("v=spf1 a mx ptr exists:%{i}.e.example include:x.example -all")

    assert record.direct_lookup_count() == 5


def test_a_redirect_costs_a_lookup():
    assert parse_spf("v=spf1 redirect=x.example").direct_lookup_count() == 1


def test_a_bare_a_mechanism_counts():
    assert parse_spf("v=spf1 a -all").direct_lookup_count() == 1


def test_an_a_mechanism_with_a_domain_counts_once():
    record = parse_spf("v=spf1 a:mail.example.net -all")

    assert record.direct_lookup_count() == 1


# --- the record as a whole --------------------------------------------------


def test_the_raw_record_is_kept_for_evidence():
    text = "v=spf1 include:_spf.example.net -all"

    assert parse_spf(text).raw == text


def test_includes_are_listed_for_chain_resolution():
    record = parse_spf("v=spf1 include:a.example include:b.example -all")

    assert record.include_targets() == ["a.example", "b.example"]


def test_a_redirect_is_part_of_the_chain_to_resolve():
    record = parse_spf("v=spf1 include:a.example redirect=b.example")

    assert record.chain_targets() == ["a.example", "b.example"]


def test_an_spf_record_reports_its_own_shape_for_evidence():
    record: SpfRecord = parse_spf("v=spf1 include:a.example ~all")

    assert record.to_dict()["terms"][0]["mechanism"] == "include"
