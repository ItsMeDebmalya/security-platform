"""ADR-034: every scanner declares its vantage and engagement, and every finding it
produces carries them. No finding carries a state_change in the Alpha."""

from __future__ import annotations

import pytest

from core.registry import discover
from tests.contract.test_not_applicable_contract import CASES


@pytest.mark.parametrize("name", sorted(discover().names()))
def test_every_registered_scanner_declares_its_tags(name):
    scanner = discover().get(name)
    assert scanner.vantage == "external_unauthenticated"
    assert scanner.engagement == "defensive"


@pytest.mark.parametrize(("scanner", "case"), CASES, ids=[f"{s}:{c['id']}" for s, c in CASES])
def test_every_corpus_finding_carries_its_scanner_s_tags_and_no_state_change(scanner, case):
    from cli.corpus import _run_case
    from core.http import MissingFixtureError

    try:
        result = _run_case(scanner, case)
    except MissingFixtureError:
        pytest.skip("fixtures do not cover this scanner version")

    declared = discover().get(scanner)
    for finding in result.findings:
        assert (finding.vantage, finding.engagement) == (declared.vantage, declared.engagement), (
            f"{finding.check_id}@{finding.location}"
        )
        assert finding.state_change is None
