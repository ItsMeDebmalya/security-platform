"""ADR-032: no check may use `not_applicable` with a reason it did not declare.

`not_applicable` leaves the inconclusive gate, so it must never be a way around
it. Each scanner declares, per check in its `CHECKS` table, which registered
reasons that check may give. The corpus half runs **every registered scanner**
that has a corpus; the second half proves the check bites.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml

from core.applicability import REASONS, undeclared
from core.models import CheckRun
from core.registry import discover

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "corpus" / "targets"


def _declared(scanner: str) -> dict[str, frozenset[str]]:
    try:
        checks = importlib.import_module(f"scanners.{scanner}.checks").CHECKS
    except (ModuleNotFoundError, AttributeError):
        return {}
    return {cid: getattr(c, "not_applicable_reasons", frozenset()) for cid, c in checks.items()}


def _cases() -> list[tuple[str, dict]]:
    cases = []
    for name in sorted(discover().names()):
        path = TARGETS / f"{name}.yaml"
        if path.exists():
            cases += [(name, case) for case in yaml.safe_load(path.read_text())["cases"]]
    return cases


CASES = _cases()


@pytest.mark.parametrize("scanner", sorted(discover().names()))
def test_every_declared_reason_is_registered(scanner):
    for check_id, reasons in _declared(scanner).items():
        assert reasons <= set(REASONS), f"{scanner}:{check_id} declares {reasons - set(REASONS)}"


@pytest.mark.parametrize(("scanner", "case"), CASES, ids=[f"{s}:{c['id']}" for s, c in CASES])
def test_no_corpus_case_uses_an_undeclared_reason(scanner, case):
    from cli.corpus import _run_case
    from core.http import MissingFixtureError

    try:
        result = _run_case(scanner, case)
    except MissingFixtureError:
        pytest.skip("fixtures do not cover this scanner version; make corpus reports it")

    assert undeclared(result.telemetry.checks_run, _declared(scanner)) == []


def test_the_contract_bites_on_a_reason_the_check_never_declared():
    runs = [CheckRun(check_id="dkim-missing", outcome="not_applicable", reason="special-use-name")]

    assert undeclared(runs, _declared("email")) == ["dkim-missing@$: special-use-name"]


def test_the_contract_accepts_a_declared_reason():
    runs = [CheckRun(check_id="x", outcome="not_applicable", reason="special-use-name")]

    assert undeclared(runs, {"x": frozenset({"special-use-name"})}) == []
