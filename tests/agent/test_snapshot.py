"""B1: the snapshot format (spec section 4) as construction helpers."""

import json

import pytest

from agent import snapshot


def _entries():
    return [
        snapshot.entry("os_release", "collected"),
        snapshot.entry("packages", "collected"),
        snapshot.entry("listening", "error", error="command_failed:ss:127"),
        snapshot.entry("accounts", "unavailable", reason="needs_root"),
    ]


def _build(**kw):
    sections = kw.pop("sections", {"os_release": {"id": "ubuntu"}, "packages": {"items": []}})
    return snapshot.build(kw.pop("manifest", _entries()), sections, kw.pop("counts", {}), **kw)


def test_build_has_the_documented_shape():
    snap = _build()
    for key in (
        "snapshot_version",
        "schema",
        "collector_version",
        "collected_at",
        "clock",
        "host",
        "manifest",
        "sections",
        "receipt",
        "self_hash",
        "counts",
    ):
        assert key in snap
    assert snap["schema"] == "security-platform/host-snapshot"
    assert isinstance(snap["snapshot_version"], int)


def test_unknown_status_is_impossible_to_construct():
    with pytest.raises(ValueError):
        snapshot.entry("x", "mostly_fine")


def test_unavailable_needs_reason_and_error_needs_error():
    with pytest.raises(ValueError):
        snapshot.entry("x", "unavailable")
    with pytest.raises(ValueError):
        snapshot.entry("x", "error")
    with pytest.raises(ValueError):
        snapshot.entry("x", "collected", reason="needs_root")


def test_manifest_and_sections_cannot_disagree():
    with pytest.raises(ValueError):  # collected but missing body
        _build(sections={"os_release": {}})
    with pytest.raises(ValueError):  # body for a section the manifest never declared
        _build(sections={"os_release": {}, "packages": {}, "ghost": {}})
    with pytest.raises(ValueError):  # duplicate manifest entry
        _build(manifest=[*_entries(), snapshot.entry("packages", "collected")])


def test_collected_empty_differs_from_unavailable_and_error():
    snap = _build(sections={"os_release": {}, "packages": []})
    by = {m["section"]: m for m in snap["manifest"]}
    assert by["packages"]["status"] == "collected" and snap["sections"]["packages"] == []
    assert by["accounts"]["status"] == "unavailable" and "accounts" not in snap["sections"]
    assert by["listening"]["status"] == "error" and "error" in by["listening"]
    assert len({by[k]["status"] for k in ("packages", "accounts", "listening")}) == 3


def test_counts_are_named_derived_and_have_no_requests():
    snap = _build(counts={"commands_run": 11, "bytes_read": 5})
    c = snap["counts"]
    assert "requests" not in c
    assert (c["sections_collected"], c["sections_unavailable"], c["sections_error"]) == (2, 1, 1)
    assert c["commands_run"] == 11 and c["files_read"] == 0
    with pytest.raises(ValueError):
        _build(counts={"requests": 3})
    with pytest.raises(ValueError):
        _build(counts={"sections_collected": 9})
    with pytest.raises(ValueError):
        _build(counts={"commands_run": "11"})


def test_self_hash_recompute_matches():
    snap = _build()
    assert snap["self_hash"].startswith("sha256:")
    assert snapshot.compute_hash(snap) == snap["self_hash"]
    assert snapshot.verify(snap)
    assert snapshot.verify(json.loads(snapshot.dumps(snap)))


def test_self_hash_excludes_itself():
    snap = _build()
    other = dict(snap, self_hash="sha256:junk")
    assert snapshot.compute_hash(other) == snap["self_hash"]


def test_single_mutated_byte_is_detected():
    text = snapshot.dumps(_build(host={"hostname": "web-01"}))
    assert snapshot.verify(json.loads(text))
    mutated = text.replace("web-01", "web-02")
    assert len(mutated) == len(text)
    assert not snapshot.verify(json.loads(mutated))


def test_docstring_says_corruption_not_tampering():
    doc = (snapshot.verify.__doc__ or "").lower()
    assert "corruption" in doc and "not tamper" in doc


def test_dumps_is_newline_terminated_utf8_json():
    text = snapshot.dumps(_build())
    assert text.endswith("\n")
    text.encode("utf-8")
