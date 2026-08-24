"""Generate the frozen DNS fixtures for the email scanner's corpus.

Each case is a synthetic zone with a known-correct answer. The fixtures are
recorded by **running the scanner itself** through a recording resolver, so
what gets frozen is exactly the set of queries the scanner makes - including
the second-resolver validation queries, which are easy to forget when writing
fixtures by hand and whose absence would silently turn validation into a
no-op on replay.

Re-run after changing which names the scanner queries:

    uv run python -m corpus.generators.email

Fixtures are one JSON file per (name, rrtype, resolver). That is verbose, and
deliberately so: ground-truth data has to be auditable by a human reading a
diff, not just by the harness.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.context import ScanContext
from core.dns import DnsClient, DnsResponse, FakeResolver, RecordingResolver
from core.models import Asset
from scanners.email import EmailScanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus" / "fixtures" / "email"

RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzE6PIiHT/sKrAyfdiCc+a7kdmUWcniaPH9J"
    "hGYxO8vRORbkz/GQFZUNN0kogF3TDDqX9263KJe/yX5+/xoJFDBEOoBX9a8uuOA6BCNImyoHiQ6YWB9b"
    "LH0ciUhVHvGjZhH7BGbJMuE/y+eh2uw6APj+7qOpnAs6jyYvOr8LlHDVURaaptx8j9AJx8GHyTD1pzSI"
    "y6Cum9di5IL5/I8Ewx7eT5DJ4Z9Gu+8dQdCi431Qbwe0t+4OpdmsBpbDnj333VSUVlI7UIgdAubpCw4Z"
    "cqFDIy7vYmlPCrdOZ2J4bpPaLGNslkG+YjZ/X5NScgG/mcds+03QvWh4XrpVxNnHTQIDAQAB"
)
RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxntLCj4ULaZcJl5J7HXYk0ANV4ZXEi2D6IZMpEhJ3"
    "H7ntz5ANAY/JQki9S6ZvTQB546YA1ShEXqc5f/r1HtJXQTi6lBkTIWYq1Go3e8vm+uWFT+Hjyv394AqB"
    "cEzch8jRI4zqiOwvW2PDQGxHesiUr7LU3xonJCBNP0oQk9CkcwIDAQAB"
)


def rr(name, rrtype, *records, rcode="NOERROR", ttl=300):
    return DnsResponse(name=name, rrtype=rrtype, rcode=rcode, records=list(records), ttl=ttl)


def zone(
    domain,
    *,
    spf=None,
    extra_txt=(),
    dmarc=None,
    mx=("10 mx1.mailhost.example.",),
    dkim=None,
    mta_sts="v=STSv1; id=20260822T000000;",
    tls_rpt=None,
    includes=None,
):
    answers = {}
    txt = [*extra_txt]
    if spf:
        txt.append(spf)
    answers[(domain, "TXT")] = rr(domain, "TXT", *txt)
    answers[(domain, "MX")] = rr(domain, "MX", *mx)
    answers[(f"_dmarc.{domain}", "TXT")] = rr(
        f"_dmarc.{domain}", "TXT", *([dmarc] if dmarc else [])
    )
    answers[(f"_mta-sts.{domain}", "TXT")] = rr(
        f"_mta-sts.{domain}", "TXT", *([mta_sts] if mta_sts else [])
    )
    answers[(f"_smtp._tls.{domain}", "TXT")] = rr(
        f"_smtp._tls.{domain}", "TXT", *([tls_rpt] if tls_rpt else [])
    )
    for selector, record in (dkim or {}).items():
        name = f"{selector}._domainkey.{domain}"
        answers[(name, "TXT")] = rr(name, "TXT", record)
    for name, record in (includes or {}).items():
        answers[(name, "TXT")] = rr(name, "TXT", record)
    return answers


GOOD = dict(
    spf="v=spf1 include:_spf.mailhost.example -all",
    dmarc=("v=DMARC1; p=reject; rua=mailto:dmarc@corpus-good.example; adkim=s; aspf=s"),
    dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_2048}"},
    tls_rpt="v=TLSRPTv1; rua=mailto:tls@corpus-good.example",
    includes={"_spf.mailhost.example": "v=spf1 ip4:192.0.2.0/24 -all"},
)


def good(domain, **overrides):
    settings = {**GOOD, **overrides}
    settings.setdefault("includes", {})
    settings["includes"] = {
        "_spf.mailhost.example": "v=spf1 ip4:192.0.2.0/24 -all",
        **settings["includes"],
    }
    if "dmarc" not in overrides:
        settings["dmarc"] = f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; adkim=s; aspf=s"
    if "tls_rpt" not in overrides:
        settings["tls_rpt"] = f"v=TLSRPTv1; rua=mailto:tls@{domain}"
    return zone(domain, **settings)


def long_chain(domain):
    """An eleven-lookup SPF policy: six includes, each costing one more lookup."""
    answers = good(
        domain,
        spf="v=spf1 " + " ".join(f"include:i{i}.chain.example" for i in range(6)) + " -all",
    )
    for i in range(6):
        answers[(f"i{i}.chain.example", "TXT")] = rr(f"i{i}.chain.example", "TXT", "v=spf1 a -all")
    return answers


class ServfailResolver:
    """Every lookup fails. The scanner must say so, not guess."""

    def resolve(self, name, rrtype, resolver=None):
        return DnsResponse(name=name, rrtype=rrtype, rcode="SERVFAIL", records=[], ttl=None)


CASES: dict[str, tuple[str, object, str]] = {
    "known-good": ("corpus-good.example", good("corpus-good.example"), "standard"),
    "null-mx": (
        "corpus-nomail.example",
        good("corpus-nomail.example", mx=("0 .",), spf="v=spf1 -all"),
        "standard",
    ),
    "nothing-configured": (
        "corpus-bare.example",
        zone("corpus-bare.example", spf=None, dmarc=None, mx=(), mta_sts=None),
        "standard",
    ),
    "dmarc-monitoring-only": (
        "corpus-pnone.example",
        good(
            "corpus-pnone.example",
            dmarc="v=DMARC1; p=none; rua=mailto:dmarc@corpus-pnone.example; adkim=s; aspf=s",
        ),
        "standard",
    ),
    "dmarc-partial-rollout": (
        "corpus-pct.example",
        good(
            "corpus-pct.example",
            dmarc="v=DMARC1; p=reject; pct=20; rua=mailto:d@corpus-pct.example; adkim=s; aspf=s",
        ),
        "standard",
    ),
    "dmarc-no-reporting": (
        "corpus-norua.example",
        good("corpus-norua.example", dmarc="v=DMARC1; p=reject; adkim=s; aspf=s"),
        "standard",
    ),
    "dmarc-malformed": (
        "corpus-baddmarc.example",
        good(
            "corpus-baddmarc.example",
            dmarc="v=DMARC1; rua=mailto:d@corpus-baddmarc.example; p=reject",
        ),
        "standard",
    ),
    "dmarc-relaxed-alignment": (
        "corpus-relaxed.example",
        good(
            "corpus-relaxed.example",
            dmarc="v=DMARC1; p=reject; rua=mailto:d@corpus-relaxed.example",
        ),
        "standard",
    ),
    "spf-invalid": (
        "corpus-badspf.example",
        good("corpus-badspf.example", spf="v=spf1 frobnicate:x ip4:999.0.2.0/24 -all"),
        "standard",
    ),
    "spf-duplicate": (
        "corpus-dupspf.example",
        good(
            "corpus-dupspf.example",
            spf="v=spf1 ip4:192.0.2.0/24 -all",
            extra_txt=["v=spf1 include:_spf.mailhost.example ~all"],
        ),
        "standard",
    ),
    "spf-permissive": (
        "corpus-plusall.example",
        good("corpus-plusall.example", spf="v=spf1 ip4:192.0.2.0/24 +all"),
        "standard",
    ),
    "spf-lookup-limit": ("corpus-chain.example", long_chain("corpus-chain.example"), "standard"),
    "dkim-weak-key": (
        "corpus-weakdkim.example",
        good("corpus-weakdkim.example", dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_1024}"}),
        "standard",
    ),
    "no-transport-security": (
        "corpus-notls.example",
        good("corpus-notls.example", mta_sts=None, tls_rpt=None),
        "standard",
    ),
    "dkim-not-discoverable": (
        "corpus-nodkim.example",
        good("corpus-nodkim.example", dkim={}),
        "standard",
    ),
    "servfail": ("corpus-broken.example", ServfailResolver(), "standard"),
}


def generate() -> None:
    for case_id, (domain, answers, mode) in CASES.items():
        directory = FIXTURES / case_id
        if directory.exists():
            shutil.rmtree(directory)
        inner = answers if not isinstance(answers, dict) else FakeResolver(answers)
        ctx = ScanContext(
            dns=DnsClient(
                resolver=RecordingResolver(inner, directory), resolvers=["1.1.1.1", "8.8.8.8"]
            ),
            progress=lambda message, fraction: None,
        )
        result = EmailScanner().run(Asset(type="domain", value=domain), mode, ctx)
        reported = [
            f.check_id for f in result.findings if f.state in ("confirmed", "highly_likely")
        ]
        inconclusive = [f.check_id for f in result.findings if f.state == "inconclusive"]
        print(
            f"{case_id:<24} {len(list(directory.iterdir())):>3} fixtures  "
            f"reported={reported} inconclusive={inconclusive}"
        )


if __name__ == "__main__":
    generate()
