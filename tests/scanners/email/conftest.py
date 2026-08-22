"""Zone builders for the email scanner tests."""

from __future__ import annotations

import pytest

from core.context import ScanContext
from core.dns import DnsClient, DnsResponse, FakeResolver
from core.models import Asset

RSA_2048_P = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzE6PIiHT/sKrAyfdiCc+a7kdmUWcniaPH9J"
    "hGYxO8vRORbkz/GQFZUNN0kogF3TDDqX9263KJe/yX5+/xoJFDBEOoBX9a8uuOA6BCNImyoHiQ6YWB9b"
    "LH0ciUhVHvGjZhH7BGbJMuE/y+eh2uw6APj+7qOpnAs6jyYvOr8LlHDVURaaptx8j9AJx8GHyTD1pzSI"
    "y6Cum9di5IL5/I8Ewx7eT5DJ4Z9Gu+8dQdCi431Qbwe0t+4OpdmsBpbDnj333VSUVlI7UIgdAubpCw4Z"
    "cqFDIy7vYmlPCrdOZ2J4bpPaLGNslkG+YjZ/X5NScgG/mcds+03QvWh4XrpVxNnHTQIDAQAB"
)
RSA_1024_P = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxntLCj4ULaZcJl5J7HXYk0ANV4ZXEi2D6IZMpEhJ3"
    "H7ntz5ANAY/JQki9S6ZvTQB546YA1ShEXqc5f/r1HtJXQTi6lBkTIWYq1Go3e8vm+uWFT+Hjyv394AqB"
    "cEzch8jRI4zqiOwvW2PDQGxHesiUr7LU3xonJCBNP0oQk9CkcwIDAQAB"
)


def answer(name, rrtype, *records, rcode="NOERROR", ttl=300):
    return DnsResponse(name=name, rrtype=rrtype, rcode=rcode, records=list(records), ttl=ttl)


def zone(
    domain,
    *,
    spf=None,
    dmarc=None,
    mx=("10 mx1.example.net.",),
    dkim=None,
    mta_sts=None,
    tls_rpt=None,
    extra_txt=(),
):
    """Build a DNS zone for one domain, as the scanner will query it."""
    answers = {}
    txt = list(extra_txt)
    if spf is not None:
        txt.append(spf)
    answers[(domain, "TXT")] = answer(domain, "TXT", *txt)
    answers[(domain, "MX")] = answer(domain, "MX", *mx)
    answers[(f"_dmarc.{domain}", "TXT")] = answer(
        f"_dmarc.{domain}", "TXT", *([dmarc] if dmarc else [])
    )
    if mta_sts:
        answers[(f"_mta-sts.{domain}", "TXT")] = answer(f"_mta-sts.{domain}", "TXT", mta_sts)
    if tls_rpt:
        answers[(f"_smtp._tls.{domain}", "TXT")] = answer(f"_smtp._tls.{domain}", "TXT", tls_rpt)
    if dkim:
        for selector, record in dkim.items():
            name = f"{selector}._domainkey.{domain}"
            answers[(name, "TXT")] = answer(name, "TXT", record)
    return answers


@pytest.fixture
def run_scan():
    from scanners.email import EmailScanner

    def _run(domain, answers, mode="light", resolvers=("1.1.1.1", "8.8.8.8")):
        ctx = ScanContext(dns=DnsClient(resolver=FakeResolver(answers), resolvers=list(resolvers)))
        return EmailScanner().run(Asset(type="domain", value=domain), mode, ctx)

    return _run


@pytest.fixture
def findings_for(run_scan):
    def _find(domain, answers, check_id, mode="light"):
        result = run_scan(domain, answers, mode)
        return [f for f in result.findings if f.check_id == check_id]

    return _find
