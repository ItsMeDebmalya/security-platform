"""F1 / F1b: the snapshot reader. Every failure is a scan error, never a truncation,
a coercion or a clear. The snapshot is hostile input (spec 13)."""

from __future__ import annotations

import json

import pytest
from host_snapshots import make_snapshot, rehash, to_bytes

from scanners.host import reader
from scanners.host.reader import SnapshotError

# --- F1: a broken snapshot ----------------------------------------------------------


def test_a_good_snapshot_reads(clean_snapshot):
    snap = reader.parse(to_bytes(clean_snapshot))
    assert snap.hostname == "lab-vm-1"
    assert snap.host_ref == "sha256:474cbba19098a942"
    assert snap.unassessed is None
    assert set(snap.manifest) >= {"kernel", "packages", "ssh"}


def test_unknown_snapshot_version_is_a_scan_error(clean_snapshot):
    clean_snapshot["snapshot_version"] = 2
    with pytest.raises(SnapshotError, match="snapshot_version"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_a_collected_section_the_manifest_promised_but_did_not_deliver(clean_snapshot):
    del clean_snapshot["sections"]["ssh"]
    with pytest.raises(SnapshotError, match="ssh"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_a_section_body_the_manifest_does_not_declare(clean_snapshot):
    clean_snapshot["sections"]["listening"] = {"x": 1}
    with pytest.raises(SnapshotError, match="listening"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_a_body_present_for_a_non_collected_section(clean_snapshot):
    clean_snapshot["sections"]["os_release"] = {"name": "x"}
    with pytest.raises(SnapshotError, match="os_release"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b'{"a": ', b"\xff\xfe\x00"])
def test_malformed_is_a_scan_error(raw):
    with pytest.raises(SnapshotError):
        reader.parse(raw)


def test_self_hash_mismatch_is_named(clean_snapshot):
    clean_snapshot["sections"]["ssh"]["permitrootlogin"] = "yes"  # changed after sealing
    with pytest.raises(SnapshotError, match="self_hash") as err:
        reader.parse(to_bytes(clean_snapshot))
    assert "sha256:" in str(err.value)  # names both hashes


def test_duplicate_keys_are_refused():
    with pytest.raises(SnapshotError, match="duplicate"):
        reader.parse(b'{"a": 1, "a": 2}')


def test_nan_is_refused(clean_snapshot):
    raw = to_bytes(clean_snapshot).replace(b'"truncated": false', b'"truncated": NaN')
    with pytest.raises(SnapshotError):
        reader.parse(raw)


def test_all_unsupported_runtime_is_unassessed_and_named():
    from agent.__main__ import unsupported_snapshot

    snap = unsupported_snapshot("2.7.18", "/usr/bin/python")
    snap["host"]["hostname"] = "old-box"
    snap["self_hash"] = None
    from agent import snapshot as agent_snapshot

    snap["self_hash"] = agent_snapshot.compute_hash(snap)
    read = reader.parse(json.dumps(snap).encode())
    assert read.unassessed == "unsupported_runtime"
    assert read.hostname == "old-box"
    assert read.host_ref is None  # no identity was collected, and none is invented


def test_one_unsupported_section_alone_is_not_unassessed(clean_snapshot):
    assert reader.parse(to_bytes(clean_snapshot)).unassessed is None


# --- F1b: pre-parse limits, each a named constant with its reason ----------------------


@pytest.mark.parametrize("name", ["MAX_BYTES", "MAX_DEPTH", "MAX_STRING", "MAX_ARRAY", "MAX_KEYS"])
def test_every_limit_is_a_named_constant_with_its_reason(name):
    assert isinstance(getattr(reader, name), int)
    assert reader.LIMIT_REASONS[name].strip()


def test_total_size_over_the_limit_is_refused_before_parsing(monkeypatch):
    monkeypatch.setattr(reader, "MAX_BYTES", 100)
    parsed = []
    monkeypatch.setattr(reader.json, "loads", lambda *a, **k: parsed.append(1))
    with pytest.raises(SnapshotError, match="MAX_BYTES"):
        reader.parse(b" " * 101)
    assert parsed == []  # refused on the raw bytes, before the parser saw anything


def test_nesting_depth_is_refused_before_parsing():
    deep = b"[" * (reader.MAX_DEPTH + 1) + b"]" * (reader.MAX_DEPTH + 1)
    with pytest.raises(SnapshotError, match="MAX_DEPTH"):
        reader.parse(deep)


def test_a_million_deep_nesting_does_not_reach_the_parser():
    with pytest.raises(SnapshotError, match="MAX_DEPTH"):
        reader.parse(b"[" * 1_000_000)


def test_string_length_is_refused_not_truncated(clean_snapshot):
    clean_snapshot["host"]["hostname"] = "a" * (reader.MAX_STRING + 1)
    with pytest.raises(SnapshotError, match="MAX_STRING"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_array_length_is_refused_not_truncated(clean_snapshot):
    clean_snapshot["receipt"]["commands_refused"] = [{}] * (reader.MAX_ARRAY + 1)
    with pytest.raises(SnapshotError, match="MAX_ARRAY"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_total_key_count_is_refused(monkeypatch, clean_snapshot):
    monkeypatch.setattr(reader, "MAX_KEYS", 10)
    with pytest.raises(SnapshotError, match="MAX_KEYS"):
        reader.parse(to_bytes(clean_snapshot))


def test_a_limit_exactly_met_is_not_refused(monkeypatch, clean_snapshot):
    raw = to_bytes(clean_snapshot)
    monkeypatch.setattr(reader, "MAX_BYTES", len(raw))
    reader.parse(raw)


def test_bracket_characters_inside_strings_do_not_count_as_depth(clean_snapshot):
    clean_snapshot["host"]["os"] = {"note": "[" * 500 + "{" * 500}
    reader.parse(to_bytes(rehash(clean_snapshot)))


def test_a_file_over_the_size_limit_is_refused_without_reading_it(tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * 50)
    monkeypatch.setattr(reader, "MAX_BYTES", 10)
    with pytest.raises(SnapshotError, match="MAX_BYTES"):
        reader.load_file(path)


def test_a_missing_file_is_a_scan_error(tmp_path):
    with pytest.raises(SnapshotError, match="snapshot file"):
        reader.load_file(tmp_path / "nope.json")


# --- F1b: no snapshot value becomes a path, argument, URL, identifier or format string ----


HOSTILE_NAMES = [
    "../../etc/passwd",
    "/dev/stdin",
    "evil\x00name",
    "a" * 4096,
    ".",
    "..",
    "",
    "a b",
    "name\n",
    "%s%n",
    "x'; DROP TABLE findings;--",
]


@pytest.mark.parametrize("hostname", HOSTILE_NAMES, ids=lambda s: repr(s[:20]))
def test_a_hostile_hostname_is_a_scan_error_naming_the_field(clean_snapshot, hostname):
    clean_snapshot["host"]["hostname"] = hostname
    with pytest.raises(SnapshotError, match=r"host\.hostname"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_the_error_message_does_not_quote_hostile_bytes_raw(clean_snapshot):
    clean_snapshot["host"]["hostname"] = "\x1b[2J\x1b[1;1H<script>alert(1)</script>"
    with pytest.raises(SnapshotError) as err:
        reader.parse(to_bytes(rehash(clean_snapshot)))
    text = str(err.value)
    assert "\x1b" not in text and "<script>" not in text
    assert "host.hostname" in text


def test_hostile_free_text_is_kept_as_data_and_opens_nothing(clean_snapshot, monkeypatch):
    """A kernel string of `/dev/stdin` is a string to display. Nothing is opened for it."""
    opened = []
    import builtins

    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda *a, **k: opened.append(a) or real_open(*a, **k))
    clean_snapshot["sections"]["kernel"]["running_version_string"] = "/dev/stdin ../../etc/passwd"
    snap = reader.parse(to_bytes(rehash(clean_snapshot)))
    assert snap.sections["kernel"]["running_version_string"] == "/dev/stdin ../../etc/passwd"
    assert opened == []


def test_reader_checks_and_scanner_open_no_path_from_data():
    """Only reader.load_file may touch the filesystem, and only with the operator's argument."""
    import ast
    import pathlib

    root = pathlib.Path(reader.__file__).parent
    banned = {"open", "subprocess", "os", "pathlib", "shutil", "socket", "urllib", "sqlite3"}
    for name in ("checks.py", "scanner.py", "render.py"):
        if not (root / name).exists():
            continue
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                hit = {a.name.split(".")[0] for a in node.names} & banned
            elif isinstance(node, ast.ImportFrom):
                hit = {(node.module or "").split(".")[0]} & banned
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                hit = {node.func.id} & banned
            else:
                continue
            assert not hit, f"{name} uses {sorted(hit)}: a snapshot value must never reach those"


# --- F1b: types validated, not coerced; the error names the field -------------------------


def _wrong(snap, path, value):
    node = snap
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return snap if path == ["self_hash"] else rehash(snap)


@pytest.mark.parametrize(
    "path,value,field",
    [
        (["host"], "a string", "host"),
        (["host", "hostname"], 12345, "host.hostname"),
        (["host", "machine_id_fingerprint"], "not-a-fingerprint", "host.machine_id_fingerprint"),
        (["collected_at"], "yesterday", "collected_at"),
        (["collected_at"], 1761731404, "collected_at"),
        (["clock", "tz_offset_minutes"], "330", "clock.tz_offset_minutes"),
        (["clock", "tz_offset_minutes"], True, "clock.tz_offset_minutes"),
        (["manifest"], {"kernel": "collected"}, "manifest"),
        (["manifest", 1, "status"], "ok", "manifest.1.status"),
        (["manifest", 1, "section"], None, "manifest.1.section"),
        (["counts", "commands_run"], -1, "counts.commands_run"),
        (["counts", "commands_run"], "3", "counts.commands_run"),
        (["counts", "commands_run"], 2.5, "counts.commands_run"),
        (["counts", "sections_collected"], 99, "counts.sections_collected"),
        (["sections", "kernel", "kernel_ownership"], "mine", "sections.kernel.kernel_ownership"),
        (["sections", "kernel", "running_release"], ["6.8"], "sections.kernel.running_release"),
        (["sections", "ssh", "permitrootlogin"], None, "sections.ssh.permitrootlogin"),
        (["sections", "packages", "items"], "linux-image", "sections.packages.items"),
        (["sections", "packages", "items", 0, "name"], 7, "sections.packages.items.0.name"),
        (["sections", "packages", "items", 0], "x", "sections.packages.items.0"),
        (["sections", "packages", "truncated"], "no", "sections.packages.truncated"),
        (["receipt", "commands"], "none", "receipt.commands"),
        (["receipt", "commands", 0, "argv"], "uname -a", "receipt.commands.0.argv"),
        (["receipt", "commands", 0, "exit_status"], "0", "receipt.commands.0.exit_status"),
        (["receipt", "commands", 0, "reason_id"], 5, "receipt.commands.0.reason_id"),
        (["self_hash"], 5, "self_hash"),
    ],
)
def test_wrong_type_is_a_scan_error_naming_the_field(clean_snapshot, path, value, field):
    snap = _wrong(clean_snapshot, path, value)
    with pytest.raises(SnapshotError) as err:
        reader.parse(to_bytes(snap))
    assert err.value.field == field, str(err.value)
    assert field in str(err.value)


def test_a_missing_required_field_names_it(clean_snapshot):
    del clean_snapshot["host"]
    with pytest.raises(SnapshotError, match="host"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_an_unknown_top_level_key_is_refused(clean_snapshot):
    clean_snapshot["extra"] = 1
    with pytest.raises(SnapshotError, match="extra"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_a_null_does_not_flow_inward(clean_snapshot):
    clean_snapshot["sections"]["kernel"]["running_release"] = None
    with pytest.raises(SnapshotError, match="running_release"):
        reader.parse(to_bytes(rehash(clean_snapshot)))


def test_make_snapshot_is_a_real_collector_shape():
    # the synthetic builder is the collector's own; if this drifts the fixtures are fiction
    from agent import snapshot as agent_snapshot

    assert agent_snapshot.verify(make_snapshot())
