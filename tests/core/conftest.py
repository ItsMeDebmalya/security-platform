"""Shared fixtures for core tests that need a real scanner's output."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def run_email_scan_with_1024_key():
    """A dkim-weak-key finding from the email scanner, on a 1024-bit key."""
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.models import Asset
    from scanners.email import EmailScanner
    from tests.scanners.email.conftest import RSA_1024_P, zone

    answers = zone(
        "weak.example",
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject",
        dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_1024_P}"},
    )
    ctx = ScanContext(
        dns=DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1", "8.8.8.8"])
    )
    result = EmailScanner().run(Asset(type="domain", value="weak.example"), "standard", ctx)
    return next(f for f in result.findings if f.check_id == "dkim-weak-key")


@pytest.fixture
def tls_finding_from_corpus():
    """A tls finding from a real lab recording, whose evidence carries certificate data."""
    from cli.corpus import TARGETS_DIR, _load, _run_case

    definition = _load(TARGETS_DIR / "tls.yaml")
    for case in definition["cases"]:
        result = _run_case("tls", case)
        for finding in result.findings:
            if "sha256" in finding.model_dump_json() or "subject" in finding.model_dump_json():
                return finding
    pytest.skip("no tls finding with certificate data in the corpus")
