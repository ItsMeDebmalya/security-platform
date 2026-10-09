"""RFC 9989 section 4.10: DMARC policy discovery by DNS Tree Walk.

The scanner used to look only at _dmarc.<target>. A subdomain whose parent
publishes DMARC was therefore reported as dmarc-missing: a false claim under
RFC 7489 and RFC 9989 alike.
"""

from __future__ import annotations

from core.dns import DnsClient, FakeResolver
from scanners.email.discovery import discover
from tests.scanners.email.conftest import answer


def client(records):
    answers = {(n, "TXT"): answer(n, "TXT", *r) for n, r in records.items()}
    return DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1", "8.8.8.8"])


def test_a_record_at_the_target_applies_and_no_walk_is_needed():
    found = discover("example.com", client({"_dmarc.example.com": ["v=DMARC1; p=reject"]}))

    assert found.source == "example.com" and not found.inherited
    assert found.record is not None and found.record.policy == "reject"


def test_a_subdomain_inherits_the_parent_record():
    found = discover("mail.example.com", client({"_dmarc.example.com": ["v=DMARC1; p=reject"]}))

    assert found.source == "example.com" and found.inherited
    assert [q.name for q in found.queried] == [
        "_dmarc.mail.example.com",
        "_dmarc.example.com",
        "_dmarc.com",
    ]


def test_an_existing_subdomain_takes_sp_when_the_parent_sets_it():
    found = discover(
        "mail.example.com", client({"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"]})
    )

    assert found.policy_tag == "sp" and found.effective.policy == "none"


def test_a_non_existent_subdomain_takes_np():
    found = discover(
        "ghost.example.com",
        client({"_dmarc.example.com": ["v=DMARC1; p=reject; sp=quarantine; np=none"]}),
        author_exists=False,
    )

    assert found.policy_tag == "np" and found.effective.policy == "none"


def test_with_records_at_two_ancestors_the_fewest_labels_wins():
    """RFC 9989 4.10.2 rule 3, and the RFC's own example."""
    found = discover(
        "a.mail.example.com",
        client(
            {
                "_dmarc.mail.example.com": ["v=DMARC1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        ),
    )

    assert found.source == "example.com"


def test_psd_n_stops_the_walk_and_names_the_organizational_domain():
    found = discover(
        "a.mail.example.com",
        client(
            {
                "_dmarc.mail.example.com": ["v=DMARC1; p=none; psd=n"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        ),
    )

    assert found.source == "mail.example.com"
    assert "_dmarc.example.com" not in [q.name for q in found.queried]


def test_a_name_with_more_than_eight_labels_is_shortened_to_seven():
    found = discover("a.b.c.d.e.f.g.h.i.j.mail.example.com", client({}))

    assert [q.name for q in found.queried] == [
        "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
        "_dmarc.g.h.i.j.mail.example.com",
        "_dmarc.h.i.j.mail.example.com",
        "_dmarc.i.j.mail.example.com",
        "_dmarc.j.mail.example.com",
        "_dmarc.mail.example.com",
        "_dmarc.example.com",
        "_dmarc.com",
    ]


def test_more_than_one_record_at_a_name_discards_them_all():
    found = discover(
        "example.com",
        client({"_dmarc.example.com": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}),
    )

    assert found.record is None
    assert found.target_records == 2


def test_a_record_without_an_exact_version_is_discarded_and_the_walk_continues():
    found = discover(
        "mail.example.com",
        client(
            {
                "_dmarc.mail.example.com": ["v=dmarc1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        ),
    )

    assert found.source == "example.com"


def test_no_record_anywhere_is_definite_and_found_nothing():
    found = discover("mail.example.com", client({}))

    assert found.record is None and found.definite


def test_a_failed_lookup_on_the_way_makes_the_walk_indefinite():
    answers = {("_dmarc.mail.example.com", "TXT"): answer("_dmarc.mail.example.com", "TXT")}
    answers[("_dmarc.example.com", "TXT")] = answer("_dmarc.example.com", "TXT", rcode="SERVFAIL")
    found = discover(
        "mail.example.com", DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1"])
    )

    assert not found.definite


def test_psd_y_makes_the_name_one_label_below_the_organizational_domain():
    """RFC 9989 4.10.2's last example: only _dmarc.com publishes, with psd=y,
    so the Organizational Domain is example.com, and with no record of its
    own the PSD's record applies."""
    found = discover("a.mail.example.com", client({"_dmarc.com": ["v=DMARC1; p=reject; psd=y"]}))

    assert found.source == "com"
    assert found.record is not None and found.record.policy == "reject"


def test_psd_y_prefers_the_organizational_domains_own_record():
    found = discover(
        "a.mail.example.com",
        client(
            {
                "_dmarc.example.com": ["v=DMARC1; p=none"],
                "_dmarc.com": ["v=DMARC1; p=reject; psd=y"],
            }
        ),
    )

    assert found.source == "example.com"
