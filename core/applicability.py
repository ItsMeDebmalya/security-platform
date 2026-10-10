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
- `CheckRun` refuses a reason that is not registered here, and the contract
  test refuses a `not_applicable` run whose reason its check did not declare
  (`tests/contract/test_not_applicable_contract.py`).

Adding a reason is a schema change (`contracts/scanresult.schema.json`
enumerates them) and an ADR-032 amendment, never an edit to a scanner alone.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import cast

from core.ids import TARGET_LEVEL
from core.models import CheckRun, NotApplicableReason

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
