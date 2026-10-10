"""ADR-031: the registry's RDAP server, from IANA's vendored bootstrap (RFC 9224)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from scanners.domscout import rdap_bootstrap as rb


def test_the_vendored_bootstrap_is_fresh():
    """ADR-031 clause 4: CI fails once the copy is older than 90 days. Refresh it
    from https://data.iana.org/rdap/dns.json and update the registry entry."""
    age = datetime.now(UTC) - rb.bootstrap().publication
    assert age <= timedelta(days=rb.MAX_AGE_DAYS), (
        f"the RDAP bootstrap was published {age.days} days ago; refresh "
        "scanners/domscout/data/iana-rdap-dns.json and tools/registry.yaml"
    )


def test_the_vendored_file_is_iana_s_and_matches_the_registry_entry():
    data = json.loads(rb.BOOTSTRAP_FILE.read_text())
    registry = (rb.BOOTSTRAP_FILE.parents[3] / "tools" / "registry.yaml").read_text()

    assert data["description"] == "RDAP bootstrap file for Domain Name System registrations"
    assert f'version: "publication {data["publication"]}"' in registry


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("amazon.in", "https://rdap.nixiregistry.in/rdap/"),
        ("sbi.co.in", "https://rdap.nixiregistry.in/rdap/"),
        ("example.com", "https://rdap.verisign.com/com/v1/"),
        ("Wikipedia.ORG.", "https://rdap.publicinterestregistry.org/rdap/"),
    ],
)
def test_a_listed_tld_maps_to_its_registry(name, base):
    assert rb.rdap_base(name) == base


def test_the_url_is_the_rfc_9082_domain_path_in_a_labels():
    assert rb.rdap_url("Amazon.IN") == "https://rdap.nixiregistry.in/rdap/domain/amazon.in"


def test_the_longest_suffix_wins(monkeypatch):
    fake = rb.Bootstrap(
        publication=datetime.now(UTC),
        services={"in": "https://a.example/", "co.in": "https://b.example/"},
    )
    monkeypatch.setattr(rb, "bootstrap", lambda: fake)

    assert rb.rdap_base("sbi.co.in") == "https://b.example/"
    assert rb.rdap_base("amazon.in") == "https://a.example/"


@pytest.mark.parametrize("name", ["codez.io", "हिंदी.भारत", "தமிழ்.இந்தியா", "nothing.arpa"])
def test_a_tld_missing_from_the_bootstrap_has_no_server(name):
    """Seen 2026-10-10: `.io` and NIXI's IDN TLDs are not in IANA's bootstrap."""
    assert rb.rdap_base(name) is None
    assert rb.rdap_url(name) is None


def test_a_name_that_does_not_encode_has_no_server():
    assert rb.rdap_base("a‍b.com") is None


@pytest.mark.parametrize(
    "name",
    [
        "corpus-x.test",
        "TEST",
        "a.b.example",
        "printer.local",
        "x.onion",
        "nas.home.arpa",
        "5.10.in-addr.arpa",
        "x.alt",
        "localhost",
    ],
)
def test_special_use_names(name):
    assert rb.is_special_use(name)


@pytest.mark.parametrize(
    "name", ["example.com", "www.example.org", "amazon.in", "testing.com", "contest", "x.arpa"]
)
def test_registered_names_are_not_special_use(name):
    """example.com/.net/.org are reserved by RFC 6761 but held by a registry."""
    assert not rb.is_special_use(name)
