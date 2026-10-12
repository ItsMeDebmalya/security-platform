"""ADR-034: every scanner declares its vantage and engagement, and every finding it
produces carries them. No finding carries a state_change in the Alpha."""

from __future__ import annotations

import pytest

from core.registry import discover
from tests.contract.test_not_applicable_contract import CASES


@pytest.mark.parametrize("name", sorted(discover().names()))
def test_every_registered_scanner_declares_its_tags(name):
    """Not hard-coded: the agent scanner (ADR-035) will declare `agent`."""
    scanner = discover().get(name)
    assert scanner.vantage is not None
    assert scanner.engagement is not None


def test_every_finding_create_in_scanners_and_core_passes_both_tags():
    """Review of ADR-034: the corpus reaches only some paths, so check every call site."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    files = [*sorted((root / "scanners").glob("*/*.py")), root / "core" / "exposure.py"]
    missing = []
    for path in files:
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "create"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "Finding"
            ):
                given = {k.arg for k in node.keywords}
                if not {"vantage", "engagement"} <= given:
                    missing.append(f"{path.relative_to(root)}:{node.lineno}")
    assert missing == []


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
