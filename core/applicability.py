"""A check that does not apply says so, and says why from a fixed list (ADR-032).

`not_applicable` is a check outcome for a target the check cannot be asked
about at all: a special-use name has no registry, so there is no registration
to expire. It is not a pass and it is not "could not tell". It sits outside
the inconclusive rate's denominator and outside TP/FP/FN, and every report
shows its count on its own.

Because it leaves the inconclusive gate, it must never become a way to avoid
it. So there is no free text:

- every reason is registered here, with its wording;
- a scanner declares, per check, which of them that check may use;
- `not_applicable` is the only constructor, and it refuses anything else;
- `CheckRun` refuses a reason that is not registered here;
- `enforce` refuses, at runtime, a result holding a `not_applicable` run whose
  reason its check did not declare. Every place that produces a result calls it
  (`scan run`, the corpus harness; `api/` must too), so a check cannot get past
  it on a code path no corpus case reaches (review of D28, finding 5);
- the contract test (`tests/contract/test_not_applicable_contract.py`) runs it
  over every scanner's corpus.

Adding a reason is a schema change (`contracts/scanresult.schema.json`
enumerates them) and an ADR-032 amendment, never an edit to a scanner alone.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Mapping
from typing import cast

from core.ids import TARGET_LEVEL
from core.models import CheckRun, NotApplicableReason, ScanResult

REASONS: dict[str, str] = {
    "special-use-name": (
        "The name is a special-use domain name (RFC 6761), which no registry delegates, "
        "so registration expiry does not apply to it."
    ),
}


def not_applicable(
    check_id: str, reason: str, *, declared: frozenset[str], location: str = TARGET_LEVEL
) -> CheckRun:
    """The `not_applicable` run for one check, if `reason` is registered and declared."""
    if reason not in REASONS:
        raise ValueError(f"{reason!r} is not a registered not_applicable reason (ADR-032)")
    if reason not in declared:
        raise ValueError(
            f"{check_id} does not declare {reason!r} among its not_applicable reasons (ADR-032)"
        )
    return CheckRun(
        check_id=check_id,
        outcome="not_applicable",
        reason=cast(NotApplicableReason, reason),
        location=location,
    )


def undeclared(
    runs: Iterable[CheckRun], declared_by_check: Mapping[str, frozenset[str]]
) -> list[str]:
    """`not_applicable` runs whose reason their check did not declare (the contract)."""
    return sorted(
        f"{run.check_id}@{run.location}: {run.reason}"
        for run in runs
        if run.outcome == "not_applicable"
        and run.reason not in declared_by_check.get(run.check_id, frozenset())
    )


class UndeclaredNotApplicableError(ValueError):
    """A `not_applicable` run with a reason its check did not declare (ADR-032)."""


def declared_reasons(scanner: str) -> dict[str, frozenset[str]]:
    """check_id -> the reasons it declared, from `scanners/<name>/checks.py`'s `CHECKS`.

    A scanner with no such table declares nothing, so it may give no reason."""
    try:
        checks = importlib.import_module(f"scanners.{scanner}.checks").CHECKS
    except (ModuleNotFoundError, AttributeError):
        return {}
    return {
        check_id: frozenset(getattr(check, "not_applicable_reasons", frozenset()))
        for check_id, check in checks.items()
    }


class StateChangeRefusedError(ValueError):
    """A result records a change made to a target, which no scan may make yet (ADR-034)."""


def enforce(result: ScanResult) -> ScanResult:
    """The result, if it keeps the safety claims that are enforced, not promised.

    - ADR-032: every `not_applicable` run's reason was declared by its check.
    - ADR-034: no finding records a `state_change`. ADR-004 is absolute until
      ADR-025's preconditions exist and a later ADR lifts this guard. A schema that
      merely permits it would leave "we don't" resting on authors' discipline;
      this makes it "we can't".
    """
    bad = undeclared(result.telemetry.checks_run, declared_reasons(result.scanner))
    if bad:
        raise UndeclaredNotApplicableError(
            f"{result.scanner} reports not_applicable with undeclared reasons: {bad} (ADR-032)"
        )
    changed = sorted(
        f"{f.check_id}@{f.location}" for f in result.findings if f.state_change is not None
    )
    if changed:
        raise StateChangeRefusedError(
            f"{result.scanner} reports changes made to a target: {changed}. No scan may "
            "change a target (ADR-004); this guard holds until a later ADR lifts it (ADR-034)"
        )
    return result
