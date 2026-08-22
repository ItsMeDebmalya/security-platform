"""Resolving the include: chain and counting its DNS lookups.

RFC 7208 4.6.4 caps a policy at 10 DNS-querying terms across the whole chain.
Exceeding it makes SPF evaluate to permerror - the policy fails entirely -
which is very commonly broken and almost never detected.
"""

from __future__ import annotations

from core.dns import DnsClient, DnsResponse, FakeResolver
from scanners.email.spf import MAX_DNS_LOOKUPS, fetch_spf, resolve_spf_chain


def _txt(name, *records, rcode="NOERROR"):
    return DnsResponse(name=name, rrtype="TXT", rcode=rcode, records=list(records), ttl=300)


def _client(answers):
    return DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1", "8.8.8.8"])


# --- fetching ---------------------------------------------------------------


def test_the_spf_record_is_picked_out_of_the_other_txt_records():
    client = _client(
        {
            ("example.com", "TXT"): _txt(
                "example.com",
                "google-site-verification=abc",
                "v=spf1 -all",
                "docusign=xyz",
            )
        }
    )

    found = fetch_spf("example.com", client)

    assert found.record is not None
    assert found.record.raw == "v=spf1 -all"


def test_two_spf_records_at_one_name_is_a_misconfiguration_not_a_parse_error():
    """RFC 7208 4.5: more than one SPF record means the evaluation is permerror."""
    client = _client(
        {
            ("example.com", "TXT"): _txt(
                "example.com", "v=spf1 -all", "v=spf1 include:a.example ~all"
            )
        }
    )

    found = fetch_spf("example.com", client)

    assert found.duplicate is True
    assert found.record is not None


def test_no_spf_record_is_reported_as_absent_not_as_an_error():
    client = _client({("example.com", "TXT"): _txt("example.com", "google-site-verification=abc")})

    found = fetch_spf("example.com", client)

    assert found.record is None
    assert found.definite is True


def test_a_servfail_is_not_an_absent_record():
    """The distinction between 'no record' and 'we could not find out'."""
    client = _client({("example.com", "TXT"): _txt("example.com", rcode="SERVFAIL")})

    found = fetch_spf("example.com", client)

    assert found.record is None
    assert found.definite is False


# --- chain resolution -------------------------------------------------------


def test_a_flat_record_costs_its_own_lookups():
    client = _client({("example.com", "TXT"): _txt("example.com", "v=spf1 a mx -all")})

    chain = resolve_spf_chain("example.com", client)

    assert chain.total_lookups == 2
    assert chain.exceeded is False


def test_an_include_adds_the_lookups_inside_it():
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 include:a.example -all"),
            ("a.example", "TXT"): _txt("a.example", "v=spf1 a mx -all"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert chain.total_lookups == 3


def test_a_chain_over_the_limit_is_flagged():
    answers = {
        ("example.com", "TXT"): _txt(
            "example.com",
            "v=spf1 " + " ".join(f"include:i{i}.example" for i in range(6)) + " -all",
        )
    }
    for i in range(6):
        answers[(f"i{i}.example", "TXT")] = _txt(f"i{i}.example", "v=spf1 a -all")

    chain = resolve_spf_chain("example.com", client=_client(answers))

    assert chain.total_lookups == 12
    assert chain.exceeded is True
    assert chain.limit == MAX_DNS_LOOKUPS


def test_a_chain_at_exactly_the_limit_is_not_flagged():
    answers = {
        ("example.com", "TXT"): _txt(
            "example.com",
            "v=spf1 " + " ".join(f"include:i{i}.example" for i in range(10)) + " -all",
        )
    }
    for i in range(10):
        answers[(f"i{i}.example", "TXT")] = _txt(f"i{i}.example", "v=spf1 -all")

    chain = resolve_spf_chain("example.com", client=_client(answers))

    assert chain.total_lookups == 10
    assert chain.exceeded is False


def test_a_redirect_is_followed_and_counted():
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 redirect=a.example"),
            ("a.example", "TXT"): _txt("a.example", "v=spf1 a -all"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert chain.total_lookups == 2


def test_an_include_loop_terminates_and_is_reported():
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 include:a.example -all"),
            ("a.example", "TXT"): _txt("a.example", "v=spf1 include:example.com -all"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert any("loop" in problem for problem in chain.problems)


def test_a_servfail_inside_the_chain_makes_the_count_inconclusive():
    """A count we could not finish is not a count."""
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 include:a.example -all"),
            ("a.example", "TXT"): _txt("a.example", rcode="SERVFAIL"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert chain.definite is False


def test_an_include_pointing_at_a_name_with_no_spf_record_is_recorded():
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 include:a.example -all"),
            ("a.example", "TXT"): _txt("a.example"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert any("a.example" in problem for problem in chain.problems)
    assert chain.definite is True


def test_the_resolved_chain_is_available_as_evidence():
    client = _client(
        {
            ("example.com", "TXT"): _txt("example.com", "v=spf1 include:a.example -all"),
            ("a.example", "TXT"): _txt("a.example", "v=spf1 a -all"),
        }
    )

    chain = resolve_spf_chain("example.com", client)

    assert [step["domain"] for step in chain.to_dict()["steps"]] == ["example.com", "a.example"]
    assert chain.to_dict()["total_lookups"] == 2
