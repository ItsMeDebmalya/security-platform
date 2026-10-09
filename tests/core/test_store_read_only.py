"""A read-only store opens, redacts in memory and writes nothing (operator, 2026-10-09).

Since D21 opening a store wrote to it (the one-time sweep), so a read-only copy
handed to a customer or an auditor no longer opened. Redaction can be re-run
safely, so a read-only store is redacted in memory as it is read instead.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from core.models import Finding
from core.store import FindingStore, ReadOnlyStoreError
from tests.core.test_redaction import GHP
from tests.core.test_redaction_review import _insert_legacy_row, _mark_unswept
from tests.core.test_redaction_storage import NOW, _finding_kwargs


def _fingerprint(path) -> tuple[str, int]:
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


@pytest.fixture
def unwritable(monkeypatch):
    """Make every path look unwritable, as a read-only copy is to a normal user."""
    real = os.access
    monkeypatch.setattr(
        "core.store.os.access", lambda p, mode: False if mode & os.W_OK else real(p, mode)
    )


def _clean_store(path) -> Finding:
    finding = Finding.create(**_finding_kwargs())
    with FindingStore(path) as store:
        store.ingest([finding])
    return finding


@pytest.mark.parametrize("how", ["explicit", "detected"])
def test_a_read_only_store_opens_and_reads(tmp_path, how, request):
    path = tmp_path / "s.db"
    finding = _clean_store(path)
    before = _fingerprint(path)
    if how == "detected":
        request.getfixturevalue("unwritable")

    with FindingStore(path, read_only=True if how == "explicit" else None) as store:
        assert store.read_only
        assert [f.id for f in store.list_findings(finding.org_id)] == [finding.id]
        assert store.get(finding.id, finding.org_id) == finding

    assert _fingerprint(path) == before


def test_a_read_only_store_written_before_adr_028_is_redacted_in_memory(tmp_path):
    path = tmp_path / "s.db"
    raw = _insert_legacy_row(path, f"/hook/{GHP}")
    _mark_unswept(path)
    before = _fingerprint(path)

    with FindingStore(path, read_only=True) as store:
        listed = store.list_findings(raw["org_id"])
        assert len(listed) == 1 and GHP not in listed[0].model_dump_json()
        new_id = listed[0].id
        assert new_id != raw["id"]
        # the same ids as after a writable store's sweep: only the redacted one
        assert store.get(new_id, raw["org_id"]) == listed[0]
        assert store.get(raw["id"], raw["org_id"]) is None

    assert _fingerprint(path) == before  # nothing written back: the file is a copy
    assert GHP in path.read_bytes().decode("latin-1")


def test_a_read_only_legacy_row_does_not_shadow_the_newer_row(tmp_path):
    path = tmp_path / "s.db"
    secret_location = f"/hook/{GHP}"
    fresh = Finding.create(**_finding_kwargs(location=secret_location))
    with FindingStore(path) as store:
        store.ingest([fresh])
        newer = store.transition(
            fresh.id, fresh.org_id, to="accepted_risk", at=NOW, by="operator:t", scan_id="s2"
        )
    _insert_legacy_row(path, secret_location)
    _mark_unswept(path)

    with FindingStore(path, read_only=True) as store:
        assert store.list_findings(fresh.org_id) == [newer]
        assert store.get(fresh.id, fresh.org_id) == newer


@pytest.mark.parametrize("write", ["ingest", "transition", "touch_last_seen"])
def test_writes_to_a_read_only_store_raise(tmp_path, write):
    path = tmp_path / "s.db"
    finding = _clean_store(path)
    before = _fingerprint(path)

    with FindingStore(path, read_only=True) as store, pytest.raises(ReadOnlyStoreError):
        if write == "ingest":
            store.ingest([finding])
        elif write == "transition":
            store.transition(finding.id, finding.org_id, to="closed", at=NOW, by="t", scan_id="s")
        else:
            store.touch_last_seen(finding.id, finding.org_id, at=NOW, scan_id="s")

    assert _fingerprint(path) == before


def test_a_missing_read_only_store_is_an_error_not_a_new_file(tmp_path):
    path = tmp_path / "absent.db"

    with pytest.raises(FileNotFoundError):
        FindingStore(path, read_only=True)
    assert not path.exists()


def test_a_writable_store_still_cleans_itself_on_disk(tmp_path):
    path = tmp_path / "s.db"
    _insert_legacy_row(path, f"/hook/{GHP}")
    _mark_unswept(path)

    with FindingStore(path) as store:
        assert not store.read_only

    assert GHP not in path.read_bytes().decode("latin-1")


# --- review of c6b3995 -----------------------------------------------------------


def test_a_store_with_no_write_bits_is_read_only_even_for_root(tmp_path):
    """A 0444 copy says "do not change me"; root could write it, but must not."""
    path = tmp_path / "s.db"
    _clean_store(path)
    path.chmod(0o444)
    before = _fingerprint(path)
    try:
        with FindingStore(path) as store:
            assert store.read_only
    finally:
        path.chmod(0o644)
    assert _fingerprint(path) == before


def test_a_symlink_is_judged_by_its_target(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    target = locked / "s.db"
    _clean_store(target)
    link = tmp_path / "link.db"
    link.symlink_to(target)
    real = os.access
    monkeypatch.setattr(
        "core.store.os.access",
        lambda p, mode: (
            False if mode & os.W_OK and str(p).startswith(str(locked)) else real(p, mode)
        ),
    )

    with FindingStore(link) as store:
        assert store.read_only


def _leave_hot_journal(path) -> None:
    import subprocess
    import sys

    code = (
        "import os, sqlite3\n"
        f"c = sqlite3.connect({str(path)!r}); c.execute('PRAGMA cache_size = 1')\n"
        "c.execute('BEGIN')\n"
        'c.execute("UPDATE findings SET data = data || hex(randomblob(4000))")\n'
        'c.execute("INSERT INTO findings SELECT id || x, org_id, scanner, check_id, "\n'
        '  "target_value, location, status, hex(randomblob(4000)) FROM findings, "\n'
        '  "(WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM r WHERE x < 300) "\n'
        '  "SELECT x FROM r)")\n'
        "os._exit(0)\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_a_read_only_store_with_a_hot_journal_says_it_needs_recovery(tmp_path):
    path = tmp_path / "s.db"
    _clean_store(path)
    _leave_hot_journal(path)
    journal = tmp_path / "s.db-journal"
    assert journal.exists()
    before, journal_before = _fingerprint(path), journal.read_bytes()

    with pytest.raises(ReadOnlyStoreError, match="recover"):
        FindingStore(path, read_only=True)

    assert _fingerprint(path) == before and journal.read_bytes() == journal_before
