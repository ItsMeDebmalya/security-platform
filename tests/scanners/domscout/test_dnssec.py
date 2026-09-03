from core.dns import DnsResponse
from scanners.domscout.dnssec import dnssec_state


def _ans(records: list[str], rcode: str = "NOERROR") -> DnsResponse:
    return DnsResponse(name="x.test", rrtype="DS", rcode=rcode, records=records)


def test_signed_when_ds_and_dnskey_present() -> None:
    assert dnssec_state(_ans(["12345 13 2 ABCD"]), _ans(["257 3 13 KEY"])) == "signed"


def test_insecure_when_both_definite_and_empty() -> None:
    assert dnssec_state(_ans([]), _ans([])) == "insecure"


def test_bogus_when_ds_present_dnskey_absent() -> None:
    assert dnssec_state(_ans(["12345 13 2 ABCD"]), _ans([])) == "bogus"


def test_inconclusive_on_servfail() -> None:
    assert dnssec_state(_ans([], rcode="SERVFAIL"), _ans([])) == "inconclusive"


def test_insecure_when_ds_absent_but_dnskey_present() -> None:
    assert dnssec_state(_ans([]), _ans(["257 3 13 KEY"])) == "insecure"


def test_inconclusive_when_dnskey_not_definite() -> None:
    assert dnssec_state(_ans(["12345 13 2 ABCD"]), _ans([], rcode="SERVFAIL")) == "inconclusive"
