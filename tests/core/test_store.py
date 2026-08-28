"""The finding store: persistence and history across re-scans (0b.8)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.store import FindingStore

SCAN_1 = "01J8AAAAAAAAAAAAAAAAAAAAAA"
SCAN_2 = "01J8BBBBBBBBBBBBBBBBBBBBBB"
SCAN_3 = "01J8CCCCCCCCCCCCCCCCCCCCCC"


@pytest.fixture
def store(tmp_path):
    with FindingStore(tmp_path / "findings.sqlite3") as fstore:
        yield fstore


def test_a_new_finding_is_stored_as_is(store, make_finding):
    finding = make_finding(first_seen_scan_id=SCAN_1, last_seen_scan_id=SCAN_1)

    store.ingest([finding])

    stored = store.get(finding.id, finding.org_id)
    assert stored is not None
    assert stored.first_seen_scan_id == SCAN_1
    assert stored.last_seen_scan_id == SCAN_1


def test_a_rescan_keeps_first_seen_and_advances_last_seen(store, make_finding):
    first = make_finding(first_seen_scan_id=SCAN_1, last_seen_scan_id=SCAN_1)
    store.ingest([first])

    second = make_finding(
        first_seen_scan_id=SCAN_2,  # a scanner has no memory; it always stamps "now"
        last_seen_scan_id=SCAN_2,
        confidence=0.99,  # something legitimately changed between scans
    )
    store.ingest([second])

    stored = store.get(first.id, first.org_id)
    assert stored is not None
    assert stored.first_seen_scan_id == SCAN_1, "first_seen must never be overwritten"
    assert stored.last_seen_scan_id == SCAN_2, "last_seen must advance on each re-observation"
    assert stored.confidence == 0.99


def test_rescan_does_not_duplicate_the_row(store, make_finding):
    finding = make_finding()
    store.ingest([finding])
    store.ingest([finding])

    assert len(store.list_findings(finding.org_id)) == 1


def test_ingest_never_closes_a_finding_absent_from_the_fresh_scan(store, make_finding):
    """The whole point: absence from one scan's findings is not evidence of a fix."""
    finding = make_finding()
    store.ingest([finding])

    store.ingest([])  # a fresh scan that didn't happen to mention this finding

    stored = store.get(finding.id, finding.org_id)
    assert stored is not None
    assert stored.status == "open"


def test_transition_appends_history_and_does_not_rewrite_it(store, make_finding):
    finding = make_finding()
    store.ingest([finding])
    at = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)

    closed = store.transition(
        finding.id, finding.org_id, to="closed", at=at, by="scan verify", scan_id=SCAN_2
    )

    assert closed.status == "closed"
    assert len(closed.status_history) == 1
    assert closed.status_history[0].to == "closed"
    assert closed.status_history[0].from_ == "open"
    assert closed.status_history[0].scan_id == SCAN_2
    assert closed.last_seen_scan_id == SCAN_2

    reopened = store.transition(
        finding.id, finding.org_id, to="open", at=at, by="scan verify", scan_id=SCAN_3
    )
    assert reopened.status == "open"
    assert len(reopened.status_history) == 2, "history is appended to, never rewritten"
    assert reopened.status_history[0].to == "closed", "the earlier entry must survive unchanged"
    assert reopened.status_history[1].to == "open"


def test_transition_to_the_same_status_is_a_no_op(store, make_finding):
    finding = make_finding()
    store.ingest([finding])
    at = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)

    unchanged = store.transition(
        finding.id, finding.org_id, to="open", at=at, by="scan verify", scan_id=SCAN_2
    )

    assert unchanged.status_history == []


def test_get_is_scoped_to_org(store, make_finding):
    finding = make_finding(org_id="org_a")
    store.ingest([finding])

    assert store.get(finding.id, "org_b") is None
    assert store.get(finding.id, "org_a") is not None


def test_transition_raises_for_an_unknown_finding(store):
    with pytest.raises(KeyError):
        store.transition(
            "sha256:" + "0" * 64,
            "org_internal",
            to="closed",
            at=datetime.now(UTC),
            by="scan verify",
            scan_id=SCAN_1,
        )
