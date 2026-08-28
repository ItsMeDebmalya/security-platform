"""The deprecation calendar — curated, sourced, reviewed data. Not logic.

docs/03-roadmap.md 0b.7: "Deadlines are versioned, sourced, reviewed data
with a lifecycle - not constants in code. A rotted clock asserts wrong
dates in our name, which is worse than not shipping one." This module is
deliberately thin: it reads `config/deprecation_calendar.yaml`, validates
it strictly, and hands back typed entries. It contains no dates itself,
computes no deadlines, and is not wired into any scanner - a scanner
turning an entry into a `derived`, dated finding (ADR-018) is later work.

**An entry without a primary source is not admissible.** D13 exists
because v3.4's research numbers came from vendor blogs and secondary
summaries and were never checked against a primary source. Every entry
here must carry `source_url` pointing at the authority's own text - a
ballot, an RFC, a standard, the vendor's own announcement of its own
change - not a summary of one. This module cannot verify that a URL is
actually a primary source; it can only insist the field is present and
looks like a URL. The discipline lives in review, not in code.

**Validation is strict and loud.** A malformed entry, a missing source, or
a missing review date is a `DeprecationCalendarError` at load time - never
a silently skipped row. Silently dropping a bad row would mean a deadline
someone wrote down is quietly not enforced anywhere, which is worse than
the file failing to load at all: a load failure is loud and gets fixed,
a dropped row looks like everything is fine.

**The staleness rule.** Curated data rots - a ballot can be amended, a
standard superseded, a vendor can walk a date back. Two failure modes are
possible when an entry has not been reviewed in a long time: refuse to
assert the date, or assert it anyway on the strength of a review that may
no longer be current. The second is a clock lying in our name, which is
exactly what the roadmap says is worse than no clock at all. So this
module treats staleness the conservative way: `active()` (the set a
scanner would be allowed to build a `derived` finding from) silently
*excludes* nothing - it never silently drops a row from the loaded set -
but it excludes stale entries from what it calls usable, and does so
loudly, by reporting them alongside the fresh ones rather than
withholding the fact. Concretely: `load()` always returns every
well-formed, sourced entry; `DeprecationCalendar.active(today)` returns
only entries reviewed within `STALE_AFTER_DAYS`; `.stale(today)` returns
the rest, so a caller (or a test, or an operator) can see exactly what
is being withheld and why, rather than a number quietly shrinking.

`STALE_AFTER_DAYS = 180`: chosen because these are slow-moving,
authority-set deadlines (standards ballots, RFCs), not fast-changing
threat data - a six-month review cadence is achievable by a two-person
team and still catches an amended ballot or a walked-back date well
before the deadline it describes arrives. If a review cadence turns out
to be too slow in practice, the number moves under the same discipline as
everything else here: a decision recorded in the ledger, not a silent
constant change.
"""

from __future__ import annotations

from datetime import date as date_
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, model_validator

from core.models import Strict

STALE_AFTER_DAYS = 180

DEFAULT_PATH = Path("config/deprecation_calendar.yaml")


class DeprecationCalendarError(ValueError):
    """A malformed, unsourced, or otherwise inadmissible calendar file.

    Raised at load time, not discovered later - see the module docstring.
    """


class DeprecationEntry(Strict):
    """One dated deadline, with its authority, source and review record.

    Mirrors the shape `docs/02-decisions.md` ADR-018 expects a scanner to
    eventually cite as `materialises_reason`: an authority, a date, and
    (via `source_url`) something a reader can go check for themselves.
    """

    id: str = Field(min_length=1)
    authority: str = Field(min_length=1)
    change: str = Field(min_length=1)
    date: date_
    source_url: str = Field(min_length=1)
    reviewed_at: date_
    reviewed_by: str = Field(min_length=1)

    @model_validator(mode="after")
    def _source_url_is_a_url(self) -> DeprecationEntry:
        if not (self.source_url.startswith("https://") or self.source_url.startswith("http://")):
            raise ValueError(
                f"{self.id}: source_url must be an http(s) URL to a primary source, "
                f"got {self.source_url!r}"
            )
        return self

    @model_validator(mode="after")
    def _reviewed_by_names_someone(self) -> DeprecationEntry:
        if self.reviewed_by.strip() == "":
            raise ValueError(f"{self.id}: reviewed_by must name a reviewer")
        return self

    def is_stale(self, *, today: date_ | None = None) -> bool:
        today = today or date_.today()
        return (today - self.reviewed_at) > timedelta(days=STALE_AFTER_DAYS)


class DeprecationCalendar:
    """The loaded, validated calendar. Construct via `load()`."""

    def __init__(self, entries: list[DeprecationEntry], source: Path | None = None) -> None:
        self._entries = entries
        self.source = source

    def all(self) -> list[DeprecationEntry]:
        """Every well-formed, sourced entry, stale or not. Never silently filtered."""
        return list(self._entries)

    def active(self, *, today: date_ | None = None) -> list[DeprecationEntry]:
        """Entries reviewed recently enough to assert. The conservative set."""
        return [e for e in self._entries if not e.is_stale(today=today)]

    def stale(self, *, today: date_ | None = None) -> list[DeprecationEntry]:
        """Entries withheld by `active()` for want of a recent review."""
        return [e for e in self._entries if e.is_stale(today=today)]

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> DeprecationCalendar:
        """Read and strictly validate the calendar file.

        A missing file is an error, not an empty calendar - unlike
        `core.authz.AuthorisedScope`, where a missing scope file is a safe
        default (no scan proceeds). There is no safe default for "no
        calendar file": either the file is meant to exist and does not
        (a deployment bug), or nothing calls this yet, in which case
        nothing should call `load()` either.
        """
        path = Path(path)
        if not path.exists():
            raise DeprecationCalendarError(f"no deprecation calendar at {path}")

        raw = yaml.safe_load(path.read_text())
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise DeprecationCalendarError(
                f"{path}: expected a YAML list of entries, got {type(raw).__name__}"
            )

        entries: list[DeprecationEntry] = []
        seen_ids: set[str] = set()
        for i, row in enumerate(raw):
            entries.append(_entry_from_row(row, path, index=i))
        for entry in entries:
            if entry.id in seen_ids:
                raise DeprecationCalendarError(f"{path}: duplicate entry id {entry.id!r}")
            seen_ids.add(entry.id)

        return cls(entries, path)


def _entry_from_row(row: Any, path: Path, *, index: int) -> DeprecationEntry:
    if not isinstance(row, dict):
        raise DeprecationCalendarError(
            f"{path}: entry {index} is not a mapping, got {type(row).__name__}"
        )
    try:
        return DeprecationEntry(**row)
    except ValidationError as exc:
        entry_id = row.get("id", f"<no id, entry {index}>")
        raise DeprecationCalendarError(f"{path}: entry {entry_id!r} is invalid: {exc}") from exc
