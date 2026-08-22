"""The one DNS client: caching, honest rcodes, kill switch, record and replay.

Everything a scanner learns about DNS comes through here. Tool 1 is pure DNS,
so this module is the difference between a trustworthy and an untrustworthy
email scanner - in particular the SERVFAIL-is-not-'missing' rule.
"""

from __future__ import annotations

import pytest

from core.dns import (
    DnsClient,
    DnsResponse,
    FakeResolver,
    MissingFixtureError,
    RecordingResolver,
    ReplayResolver,
    join_txt_chunks,
)
from core.killswitch import KillSwitch, ScanKilledError
from core.ratelimit import RateLimiter


@pytest.fixture
def answers():
    return {
        ("example.com", "TXT"): DnsResponse(
            name="example.com",
            rrtype="TXT",
            rcode="NOERROR",
            records=["v=spf1 include:_spf.example.net -all"],
            ttl=300,
        ),
        ("example.com", "MX"): DnsResponse(
            name="example.com",
            rrtype="MX",
            rcode="NOERROR",
            records=["10 mx1.example.com."],
            ttl=300,
        ),
        ("missing.example", "TXT"): DnsResponse(
            name="missing.example",
            rrtype="TXT",
            rcode="NXDOMAIN",
            records=[],
            ttl=None,
        ),
        ("broken.example", "TXT"): DnsResponse(
            name="broken.example",
            rrtype="TXT",
            rcode="SERVFAIL",
            records=[],
            ttl=None,
        ),
        ("slow.example", "TXT"): DnsResponse(
            name="slow.example",
            rrtype="TXT",
            rcode="TIMEOUT",
            records=[],
            ttl=None,
        ),
    }


@pytest.fixture
def client(answers):
    return DnsClient(resolver=FakeResolver(answers))


def test_a_query_returns_the_records_at_that_name(client):
    response = client.query("example.com", "TXT")

    assert response.records == ["v=spf1 include:_spf.example.net -all"]
    assert response.rcode == "NOERROR"


def test_a_name_that_does_not_exist_is_nxdomain_not_an_exception(client):
    response = client.query("missing.example", "TXT")

    assert response.rcode == "NXDOMAIN"
    assert response.records == []


def test_servfail_is_reported_as_servfail_and_never_as_missing(client):
    """Some providers SERVFAIL under load. That is inconclusive, not 'no record'."""
    response = client.query("broken.example", "TXT")

    assert response.rcode == "SERVFAIL"
    assert not response.is_definite()


def test_a_timeout_is_reported_and_is_not_definite(client):
    response = client.query("slow.example", "TXT")

    assert response.rcode == "TIMEOUT"
    assert not response.is_definite()


def test_nxdomain_is_a_definite_answer(client):
    assert client.query("missing.example", "TXT").is_definite()


def test_an_unknown_name_defaults_to_nxdomain_in_the_fake_resolver(client):
    assert client.query("nothing-here.example", "TXT").rcode == "NXDOMAIN"


# --- caching ----------------------------------------------------------------


def test_the_same_query_twice_hits_the_wire_once(answers):
    resolver = FakeResolver(answers)
    client = DnsClient(resolver=resolver)

    client.query("example.com", "TXT")
    client.query("example.com", "TXT")

    assert resolver.calls == [("example.com", "TXT")]


def test_different_record_types_at_one_name_are_separate_queries(answers):
    resolver = FakeResolver(answers)
    client = DnsClient(resolver=resolver)

    client.query("example.com", "TXT")
    client.query("example.com", "MX")

    assert len(resolver.calls) == 2


def test_names_are_cached_case_insensitively(answers):
    resolver = FakeResolver(answers)
    client = DnsClient(resolver=resolver)

    client.query("example.com", "TXT")
    client.query("EXAMPLE.COM", "txt")

    assert len(resolver.calls) == 1


def test_a_query_counts_towards_the_scan_cost(answers):
    from core.cost import CostMeter

    meter = CostMeter()
    client = DnsClient(resolver=FakeResolver(answers), cost=meter)

    client.query("example.com", "TXT")
    client.query("example.com", "MX")

    assert meter.snapshot().requests == 2


def test_a_cached_query_is_not_counted_twice(answers):
    from core.cost import CostMeter

    meter = CostMeter()
    client = DnsClient(resolver=FakeResolver(answers), cost=meter)

    client.query("example.com", "TXT")
    client.query("example.com", "TXT")

    assert meter.snapshot().requests == 1


# --- safety -----------------------------------------------------------------


def test_the_kill_switch_is_checked_before_every_query(answers):
    switch = KillSwitch()
    client = DnsClient(
        resolver=FakeResolver(answers), killswitch=switch, scan_id="s1", org_id="org_a"
    )
    client.query("example.com", "TXT")

    switch.kill(scan_id="s1", reason="operator")

    with pytest.raises(ScanKilledError):
        client.query("example.com", "MX")


def test_the_rate_limiter_is_consulted_per_resolver(answers):
    seen: list[str] = []

    class SpyLimiter(RateLimiter):
        def acquire(self, host: str, tokens: float = 1.0) -> None:
            seen.append(host)

    client = DnsClient(
        resolver=FakeResolver(answers), ratelimit=SpyLimiter(), resolvers=["1.1.1.1"]
    )
    client.query("example.com", "TXT")

    assert seen == ["1.1.1.1"]


# --- wildcards --------------------------------------------------------------


def test_a_zone_with_no_wildcard_is_reported_as_having_none(client):
    """DNS wildcards make every _dmarc.* lookup appear to succeed."""
    assert client.has_wildcard("example.com", "TXT") is False


def test_a_zone_that_answers_every_name_is_reported_as_wildcarded():
    class EverythingResolver:
        def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
            return DnsResponse(
                name=name, rrtype=rrtype, rcode="NOERROR", records=["v=spf1 -all"], ttl=60
            )

    client = DnsClient(resolver=EverythingResolver())

    assert client.has_wildcard("example.com", "TXT") is True


def test_wildcard_detection_is_inconclusive_when_the_probe_fails():
    class BrokenResolver:
        def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
            return DnsResponse(name=name, rrtype=rrtype, rcode="SERVFAIL", records=[], ttl=None)

    client = DnsClient(resolver=BrokenResolver())

    assert client.has_wildcard("example.com", "TXT") is None


def test_the_wildcard_probe_is_available_as_evidence(client):
    client.has_wildcard("example.com", "TXT")

    probe = client.wildcard_probe("example.com", "TXT")
    assert probe is not None
    assert probe.rcode == "NXDOMAIN"


# --- record and replay ------------------------------------------------------


def test_recorded_traffic_replays_identically_offline(answers, tmp_path):
    recording = DnsClient(resolver=RecordingResolver(FakeResolver(answers), tmp_path))
    live = recording.query("example.com", "TXT")

    replayed = DnsClient(resolver=ReplayResolver(tmp_path)).query("example.com", "TXT")

    assert replayed == live


def test_replay_preserves_a_servfail(answers, tmp_path):
    DnsClient(resolver=RecordingResolver(FakeResolver(answers), tmp_path)).query(
        "broken.example", "TXT"
    )

    assert (
        DnsClient(resolver=ReplayResolver(tmp_path)).query("broken.example", "TXT").rcode
        == "SERVFAIL"
    )


def test_replaying_a_query_that_was_never_recorded_fails_loudly(tmp_path):
    """A replay that silently goes to the wire is not a deterministic test."""
    client = DnsClient(resolver=ReplayResolver(tmp_path))

    with pytest.raises(MissingFixtureError, match=r"never-recorded\.example"):
        client.query("never-recorded.example", "TXT")


# --- TXT chunking -----------------------------------------------------------


def test_a_long_txt_record_split_across_strings_is_rejoined():
    """A >255-byte TXT record arrives as several strings and is one value."""
    assert join_txt_chunks(['"v=spf1 ip4:192.0.2.0/24 ', 'include:_spf.example.net -all"']) == (
        "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"
    )


def test_a_single_quoted_txt_string_loses_its_quotes():
    assert join_txt_chunks(['"v=DMARC1; p=none"']) == "v=DMARC1; p=none"


# --- independent re-query ---------------------------------------------------


def test_a_query_can_be_directed_at_a_named_resolver(answers):
    seen: list[str | None] = []

    class SpyResolver:
        def resolve(self, name, rrtype, resolver=None):
            seen.append(resolver)
            return answers[("example.com", "TXT")]

    client = DnsClient(resolver=SpyResolver(), resolvers=["1.1.1.1", "8.8.8.8"])
    client.query("example.com", "TXT")
    client.query("example.com", "TXT", resolver="8.8.8.8")

    assert seen == ["1.1.1.1", "8.8.8.8"]


def test_the_cache_does_not_serve_one_resolvers_answer_for_another(answers):
    resolver = FakeResolver(answers)
    client = DnsClient(resolver=resolver, resolvers=["1.1.1.1", "8.8.8.8"])

    client.query("example.com", "TXT")
    client.query("example.com", "TXT", resolver="8.8.8.8")

    assert len(resolver.calls) == 2


def test_a_second_resolver_is_available_for_independent_re_query(answers):
    client = DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1", "8.8.8.8"])

    assert client.second_resolver() == "8.8.8.8"


def test_there_is_no_second_resolver_when_only_one_is_configured(answers):
    client = DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1"])

    assert client.second_resolver() is None


def test_recordings_from_different_resolvers_do_not_overwrite_each_other(answers, tmp_path):
    class PerResolver:
        def resolve(self, name, rrtype, resolver=None):
            return DnsResponse(
                name=name,
                rrtype=rrtype,
                rcode="NOERROR",
                records=[f"answered by {resolver}"],
                ttl=60,
                resolver=resolver,
            )

    recording = DnsClient(
        resolver=RecordingResolver(PerResolver(), tmp_path), resolvers=["1.1.1.1", "8.8.8.8"]
    )
    recording.query("example.com", "TXT")
    recording.query("example.com", "TXT", resolver="8.8.8.8")

    replay = DnsClient(resolver=ReplayResolver(tmp_path), resolvers=["1.1.1.1", "8.8.8.8"])
    assert replay.query("example.com", "TXT").records == ["answered by 1.1.1.1"]
    assert replay.query("example.com", "TXT", resolver="8.8.8.8").records == ["answered by 8.8.8.8"]
