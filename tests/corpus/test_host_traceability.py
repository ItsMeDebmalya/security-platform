"""D67: an expect_inconclusive snapshot case must trace to what the snapshot holds."""

from __future__ import annotations

import json
from pathlib import Path

from cli.corpus import ROOT, declined_judgement_gaps


def _write(tmp_path: Path, snap: dict) -> Path:
    (tmp_path / "snapshot.json").write_text(json.dumps(snap))
    return tmp_path


def test_shared_kernel_fixture_is_traceable() -> None:
    assert declined_judgement_gaps(ROOT / "corpus/fixtures/host/shared-kernel") == []


def test_decidable_host_claiming_inconclusive_fails() -> None:
    gaps = declined_judgement_gaps(ROOT / "corpus/fixtures/host/clean")
    assert any("decidable" in g for g in gaps)


def test_omitted_section_is_not_a_decline(tmp_path: Path) -> None:
    snap = {"manifest": [{"section": "kernel", "status": "collected"}], "sections": {}}
    gaps = declined_judgement_gaps(_write(tmp_path, snap))
    assert any("ssh" in g and "omission" in g for g in gaps)


def test_non_snapshot_case_has_no_gaps(tmp_path: Path) -> None:
    assert declined_judgement_gaps(tmp_path) == []
