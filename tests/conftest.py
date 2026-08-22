"""Shared factories for contract tests.

Deliberately verbose: these build findings the way a scanner would, through
the public API, so the tests exercise the contract rather than the internals.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

CAPTURED_AT = datetime(2026, 8, 22, 9, 14, tzinfo=UTC)


@pytest.fixture
def dns_evidence() -> dict[str, Any]:
    return {
        "kind": "dns_answer",
        "label": "TXT at _dmarc.example.com",
        "test": {
            "query": {"name": "_dmarc.example.com", "rrtype": "TXT", "resolver": "1.1.1.1"},
            "answer": {"rcode": "NOERROR", "records": ["v=DMARC1; p=none"], "ttl": 300},
        },
        "control": {
            "query": {
                "name": "sp-wildcard-probe-9f3a.example.com",
                "rrtype": "TXT",
                "resolver": "1.1.1.1",
            },
            "answer": {"rcode": "NXDOMAIN", "records": [], "ttl": None},
        },
        "control_rationale": "random-label probe proves the zone has no TXT wildcard",
        "captured_at": CAPTURED_AT,
    }


@pytest.fixture
def make_finding(dns_evidence: dict[str, Any]):
    from core.models import Finding

    def _make(**overrides: Any) -> Finding:
        kwargs: dict[str, Any] = {
            "org_id": "org_internal",
            "scanner": "email",
            "scanner_version": "1.0.0",
            "check_id": "dmarc-policy-none",
            "title": "DMARC policy is set to 'none'",
            "target": {"type": "domain", "value": "example.com"},
            "location": "$",
            "severity": "medium",
            "confidence": 0.97,
            "detection_methods": [
                {
                    "method": "dns_txt_parse",
                    "likelihood_ratio": 12.0,
                    "independence_class": "dns",
                    "prior": 0.5,
                    "prior_justification": "DMARC records are unambiguous when they parse",
                }
            ],
            "validation": {
                "attempted": True,
                "outcome": "passed",
                "method": "independent_reparse",
            },
            "evidence": [dns_evidence],
            "description": "The domain publishes a DMARC record whose policy is 'none'.",
            "impact": "Receiving mail servers are told to take no action on spoofed mail.",
            "remediation": "Change p=none to p=quarantine, then p=reject once rua reports are clean.",
            "first_seen": CAPTURED_AT,
            "first_seen_scan_id": "01J8ZZZZZZZZZZZZZZZZZZZZZZ",
            "last_seen": CAPTURED_AT,
            "last_seen_scan_id": "01J8ZZZZZZZZZZZZZZZZZZZZZZ",
        }
        kwargs.update(overrides)
        return Finding.create(**kwargs)

    return _make
