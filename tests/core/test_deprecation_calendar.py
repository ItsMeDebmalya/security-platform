"""The deprecation calendar loader: strict validation, loud failure, and staleness.

docs/03-roadmap.md 0b.7. Every check here is either "a bad row fails loudly at
load time" or "a stale entry is withheld from `active()` but never hidden
from `all()`" - the two disciplines the module docstring commits to.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from core.deprecation_calendar import (
    DeprecationCalendar,
    DeprecationCalendarError,
    DeprecationEntry,
)

GOOD_ENTRY = """
- id: cert-lifetime-200-days-2026-03-15
  authority: CA/Browser Forum
  change: Maximum TLS certificate validity drops to 200 days.
  date: 2026-03-15
  source_url: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
  reviewed_at: 2026-08-28
  reviewed_by: operator:satwik
"""


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "calendar.yaml"
    path.write_text(content)
    return path


def test_a_well_formed_entry_loads(tmp_path: Path):
    calendar = DeprecationCalendar.load(_write(tmp_path, GOOD_ENTRY))
    entries = calendar.all()

    assert len(entries) == 1
    assert entries[0].id == "cert-lifetime-200-days-2026-03-15"
    assert entries[0].date == date(2026, 3, 15)


def test_a_missing_file_is_an_error_not_an_empty_calendar(tmp_path: Path):
    missing = tmp_path / "does-not-exist.yaml"

    with pytest.raises(DeprecationCalendarError, match="no deprecation calendar"):
        DeprecationCalendar.load(missing)


def test_a_non_list_file_is_rejected(tmp_path: Path):
    path = _write(tmp_path, "not_a_list: true\n")

    with pytest.raises(DeprecationCalendarError, match="expected a YAML list"):
        DeprecationCalendar.load(path)


def test_an_entry_that_is_not_a_mapping_is_rejected(tmp_path: Path):
    path = _write(tmp_path, "- just a string\n")

    with pytest.raises(DeprecationCalendarError, match="not a mapping"):
        DeprecationCalendar.load(path)


def test_a_missing_source_url_fails_loudly(tmp_path: Path):
    content = """
- id: no-source
  authority: Somebody
  change: Something changes.
  date: 2027-01-01
  reviewed_at: 2026-08-28
  reviewed_by: operator:satwik
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="no-source"):
        DeprecationCalendar.load(path)


def test_a_source_url_that_is_not_a_url_fails_loudly(tmp_path: Path):
    content = """
- id: bad-source
  authority: Somebody
  change: Something changes.
  date: 2027-01-01
  source_url: "see the vendor blog"
  reviewed_at: 2026-08-28
  reviewed_by: operator:satwik
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="primary source"):
        DeprecationCalendar.load(path)


def test_a_missing_review_date_fails_loudly(tmp_path: Path):
    content = """
- id: no-review-date
  authority: Somebody
  change: Something changes.
  date: 2027-01-01
  source_url: https://example.org/primary-source
  reviewed_by: operator:satwik
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="no-review-date"):
        DeprecationCalendar.load(path)


def test_a_missing_reviewer_fails_loudly(tmp_path: Path):
    content = """
- id: no-reviewer
  authority: Somebody
  change: Something changes.
  date: 2027-01-01
  source_url: https://example.org/primary-source
  reviewed_at: 2026-08-28
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="no-reviewer"):
        DeprecationCalendar.load(path)


def test_a_malformed_date_fails_loudly(tmp_path: Path):
    content = """
- id: bad-date
  authority: Somebody
  change: Something changes.
  date: not-a-date
  source_url: https://example.org/primary-source
  reviewed_at: 2026-08-28
  reviewed_by: operator:satwik
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="bad-date"):
        DeprecationCalendar.load(path)


def test_a_duplicate_id_is_rejected(tmp_path: Path):
    content = GOOD_ENTRY + GOOD_ENTRY
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="duplicate entry id"):
        DeprecationCalendar.load(path)


def test_an_unknown_field_is_rejected(tmp_path: Path):
    content = """
- id: extra-field
  authority: Somebody
  change: Something changes.
  date: 2027-01-01
  source_url: https://example.org/primary-source
  reviewed_at: 2026-08-28
  reviewed_by: operator:satwik
  some_unexpected_field: true
"""
    path = _write(tmp_path, content)

    with pytest.raises(DeprecationCalendarError, match="extra-field"):
        DeprecationCalendar.load(path)


def test_the_real_calendar_file_loads_and_validates():
    calendar = DeprecationCalendar.load()

    assert len(calendar.all()) >= 1
    for entry in calendar.all():
        assert entry.source_url.startswith("https://") or entry.source_url.startswith("http://")


# --- staleness ---------------------------------------------------------


def _entry(reviewed_at: date, entry_id: str = "e") -> DeprecationEntry:
    return DeprecationEntry(
        id=entry_id,
        authority="Somebody",
        change="Something changes.",
        date=date(2030, 1, 1),
        source_url="https://example.org/primary-source",
        reviewed_at=reviewed_at,
        reviewed_by="operator:satwik",
    )


def test_a_recently_reviewed_entry_is_active_and_not_stale():
    today = date(2026, 8, 28)
    entry = _entry(reviewed_at=date(2026, 6, 1))
    calendar = DeprecationCalendar([entry])

    assert entry in calendar.active(today=today)
    assert entry not in calendar.stale(today=today)


def test_an_entry_unreviewed_for_over_180_days_is_stale_and_withheld_from_active():
    today = date(2026, 8, 28)
    entry = _entry(reviewed_at=date(2025, 12, 1))  # ~270 days before `today`
    calendar = DeprecationCalendar([entry])

    assert entry not in calendar.active(today=today)
    assert entry in calendar.stale(today=today)


def test_a_stale_entry_still_appears_in_all_never_silently_dropped():
    today = date(2026, 8, 28)
    entry = _entry(reviewed_at=date(2025, 12, 1))
    calendar = DeprecationCalendar([entry])

    assert entry in calendar.all()
    assert entry not in calendar.active(today=today)
