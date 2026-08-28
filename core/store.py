"""The finding store: persistence between scans (docs/03-roadmap.md 0b.8).

"We check your fix worked" needs findings to survive from one scan to the
next, keyed on the deterministic finding `id` (core/ids.py) so a re-scan
updates one row's history instead of creating a duplicate. That determinism
is exactly why `scanner_version` is excluded from the id formula: a logic
change must not look like every finding closing and reopening.

**Storage choice: SQLite, one file, one table.** Phase 6 is Postgres
(ADR-009), so the question is not "what's most convenient today" but "what
keeps that migration honest." A JSON-per-org file was considered and
rejected: it would hide the primary-key/upsert semantics Postgres enforces
behind ad-hoc dict merging, so a bug in "never overwrite first_seen" would be
caught only by tests, never by the storage layer. SQLite has a real primary
key, a real `INSERT ... ON CONFLICT DO UPDATE`, and the statements here read
almost unchanged against Postgres - the eventual migration swaps the driver
and the connection string, not the shape of the code. It ships in the
standard library, so it costs nothing today and forces nothing later.

Every row carries `org_id` (CLAUDE.md: from the first migration, even
pre-multi-tenancy), and the primary key is `(id, org_id)` - two orgs can
observe what happens to be the same deterministic id without colliding,
though in practice `org_id` is folded into no part of `finding_id` today and
that is a known simplification, not a claim that it will always hold.

`ingest()` is deliberately narrow: it upserts whatever a fresh scan reports
and never closes a finding that goes unmentioned. A finding disappearing
from one scan's output could mean the bug is fixed, or it could mean the
check didn't run - `ingest()` cannot tell the difference, so it does not
guess. Only `scan verify` (cli/main.py), which asks the check directly and
reads its outcome, is allowed to close.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Self

from core.models import Finding, Status, StatusChange

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    scanner TEXT NOT NULL,
    check_id TEXT NOT NULL,
    target_value TEXT NOT NULL,
    location TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (id, org_id)
)
"""


class FindingStore:
    """Findings keyed on their deterministic id, upserted across scans."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- reads ---------------------------------------------------------

    def get(self, finding_id: str, org_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT data FROM findings WHERE id = ? AND org_id = ?", (finding_id, org_id)
        ).fetchone()
        if row is None:
            return None
        return Finding.model_validate(json.loads(row[0]))

    def list_findings(
        self,
        org_id: str,
        *,
        target_value: str | None = None,
        status: str | None = None,
    ) -> list[Finding]:
        query = "SELECT data FROM findings WHERE org_id = ?"
        params: list[str] = [org_id]
        if target_value is not None:
            query += " AND target_value = ?"
            params.append(target_value)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        rows = self._conn.execute(query, params).fetchall()
        return [Finding.model_validate(json.loads(r[0])) for r in rows]

    # --- writes ----------------------------------------------------------

    def _put(self, finding: Finding) -> None:
        self._conn.execute(
            """
            INSERT INTO findings
                (id, org_id, scanner, check_id, target_value, location, status, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id, org_id) DO UPDATE SET
                scanner = excluded.scanner,
                check_id = excluded.check_id,
                target_value = excluded.target_value,
                location = excluded.location,
                status = excluded.status,
                data = excluded.data
            """,
            (
                finding.id,
                finding.org_id,
                finding.scanner,
                finding.check_id,
                finding.target.value,
                finding.location,
                finding.status,
                finding.model_dump_json(),
            ),
        )
        self._conn.commit()

    def ingest(self, findings: list[Finding]) -> list[Finding]:
        """Upsert a fresh scan's findings, preserving identity across the id.

        A finding not already in the store is inserted as-is. One that is
        already there keeps its `first_seen`/`first_seen_scan_id` and its
        `status`/`status_history` from the stored row - a re-scan is never
        allowed to overwrite when a finding was first seen or silently
        change its status - while everything else (confidence, evidence,
        `last_seen`/`last_seen_scan_id`, which the scanner already stamped
        with the current scan) comes from the fresh finding.

        Never closes anything: a finding this scan did not mention is left
        exactly as it was. See the module docstring for why.
        """
        stored: list[Finding] = []
        for fresh in findings:
            existing = self.get(fresh.id, fresh.org_id)
            if existing is None:
                self._put(fresh)
                stored.append(fresh)
                continue
            merged = fresh.model_copy(
                update={
                    "first_seen": existing.first_seen,
                    "first_seen_scan_id": existing.first_seen_scan_id,
                    "status": existing.status,
                    "status_history": existing.status_history,
                }
            )
            self._put(merged)
            stored.append(merged)
        return stored

    def transition(
        self,
        finding_id: str,
        org_id: str,
        *,
        to: Status,
        at: datetime,
        by: str,
        scan_id: str,
    ) -> Finding:
        """Append a status change and bump `last_seen`. Never rewrites history."""
        existing = self.get(finding_id, org_id)
        if existing is None:
            raise KeyError(f"no stored finding {finding_id!r} for org {org_id!r}")
        if existing.status == to:
            return existing
        change = StatusChange(to=to, at=at, by=by, scan_id=scan_id, **{"from": existing.status})
        updated = existing.model_copy(
            update={
                "status": to,
                "status_history": [*existing.status_history, change],
                "last_seen": at,
                "last_seen_scan_id": scan_id,
            }
        )
        self._put(updated)
        return updated

    def touch_last_seen(
        self, finding_id: str, org_id: str, *, at: datetime, scan_id: str
    ) -> Finding:
        """Record that a finding was observed again, without changing its status."""
        existing = self.get(finding_id, org_id)
        if existing is None:
            raise KeyError(f"no stored finding {finding_id!r} for org {org_id!r}")
        updated = existing.model_copy(update={"last_seen": at, "last_seen_scan_id": scan_id})
        self._put(updated)
        return updated


@dataclass(frozen=True)
class VerifyOutcome:
    """What `scan verify` decided, and why - always reported, never silent."""

    finding_id: str
    check_id: str
    action: str
    reason: str
    finding: Finding
