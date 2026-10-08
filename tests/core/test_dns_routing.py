"""D39: a query directed at a resolver must be sent to that resolver.

Until 2026-10-08 `SystemResolver.resolve()` ignored its `resolver` argument
and only stamped it on the answer, so every "independent re-query via
8.8.8.8" was asked of 1.1.1.1 and labelled 8.8.8.8. The existing routing
test used a spy resolver, so it proved the hand-off from `DnsClient`, never
the routing. These tests watch the packets: `dns.query.udp` and
`dns.query.tcp` are what dnspython calls for every Do53 query, and replacing
them records the server each packet was addressed to, with no network.
"""

from __future__ import annotations

import dns.exception
import dns.message
import dns.query
import dns.rdata
import pytest

from core.dns import DnsClient, DnsResponse, FakeResolver, SystemResolver


@pytest.fixture
def wire(monkeypatch):
    """Record where every packet goes. `answering` lists servers that reply."""
    sent: list[str] = []
    answering: set[str] = set()

    def fake(q, where, *args, **kwargs):
        sent.append(where)
        if where not in answering:
            raise dns.exception.Timeout
        response = dns.message.make_response(q)
        question = q.question[0]
        rrset = response.find_rrset(
            response.answer, question.name, question.rdclass, question.rdtype, create=True
        )
        rrset.add(
            dns.rdata.from_text(question.rdclass, question.rdtype, f'"answered-by-{where}"'), 300
        )
        # Round-trip through the wire format, as a real reply arrives.
        return dns.message.from_wire(response.to_wire())

    monkeypatch.setattr(dns.query, "udp", fake)
    monkeypatch.setattr(dns.query, "tcp", fake)
    return sent, answering


def test_a_query_for_a_named_resolver_is_sent_only_to_that_resolver(wire):
    sent, answering = wire
    answering.update({"1.1.1.1", "8.8.8.8"})
    resolver = SystemResolver(["1.1.1.1", "8.8.8.8"])

    response = resolver.resolve("example.com", "TXT", "8.8.8.8")

    assert set(sent) == {"8.8.8.8"}
    assert response.resolver == "8.8.8.8"
    assert response.records == ["answered-by-8.8.8.8"]


def test_the_primary_and_the_second_resolver_are_different_servers_on_the_wire(wire):
    sent, answering = wire
    answering.update({"1.1.1.1", "8.8.8.8"})
    client = DnsClient(
        resolver=SystemResolver(["1.1.1.1", "8.8.8.8"]), resolvers=["1.1.1.1", "8.8.8.8"]
    )

    first = client.query("example.com", "TXT")
    second = client.query("example.com", "TXT", resolver=client.second_resolver())

    assert sent == ["1.1.1.1", "8.8.8.8"]
    assert first.records == ["answered-by-1.1.1.1"]
    assert second.records == ["answered-by-8.8.8.8"]


def test_a_named_resolver_that_fails_is_not_silently_replaced_by_another(wire):
    """Falling back to 8.8.8.8 while labelling the answer 1.1.1.1 is the same
    provenance defect in a different place. A failure stays a failure."""
    sent, answering = wire
    answering.add("8.8.8.8")
    resolver = SystemResolver(["1.1.1.1", "8.8.8.8"])

    response = resolver.resolve("example.com", "TXT", "1.1.1.1")

    assert set(sent) == {"1.1.1.1"}
    assert response.rcode == "TIMEOUT"
    assert response.resolver == "1.1.1.1"


def test_an_unnamed_query_is_labelled_with_the_server_that_actually_answered(wire):
    sent, answering = wire
    answering.add("8.8.8.8")
    resolver = SystemResolver(["1.1.1.1", "8.8.8.8"])

    response = resolver.resolve("example.com", "TXT")

    assert sent[0] == "1.1.1.1" and sent[-1] == "8.8.8.8"  # fell back, honestly
    assert response.resolver == "8.8.8.8"
    assert response.records == ["answered-by-8.8.8.8"]


def test_the_fake_resolver_can_express_two_resolvers_disagreeing():
    """Condition (a): without this the corpus cannot test the confirmation step."""
    base = DnsResponse(name="x.example", rrtype="TXT", rcode="NOERROR", records=["v=spf1 -all"])
    stale = DnsResponse(name="x.example", rrtype="TXT", rcode="NOERROR", records=[])
    fake = FakeResolver(
        {("x.example", "TXT"): base}, by_resolver={"8.8.8.8": {("x.example", "TXT"): stale}}
    )

    assert fake.resolve("x.example", "TXT", "1.1.1.1").records == ["v=spf1 -all"]
    assert fake.resolve("x.example", "TXT", "8.8.8.8").records == []


def test_the_fake_resolver_labels_answers_with_the_resolver_asked():
    base = DnsResponse(name="x.example", rrtype="TXT", rcode="NOERROR", records=["a"])
    fake = FakeResolver({("x.example", "TXT"): base})

    assert fake.resolve("x.example", "TXT", "8.8.8.8").resolver == "8.8.8.8"
    assert fake.resolve("nope.example", "TXT", "9.9.9.9").resolver == "9.9.9.9"
    assert fake.routed == [("x.example", "TXT", "8.8.8.8"), ("nope.example", "TXT", "9.9.9.9")]
