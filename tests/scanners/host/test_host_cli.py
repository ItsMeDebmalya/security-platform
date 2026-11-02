"""6c: `scan run host --snapshot <file>` and the registry entry."""

from __future__ import annotations

import json

import pytest
from host_snapshots import PKG_NEW, PKG_OLD, make_snapshot, rehash, to_bytes
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def _file(tmp_path, snap, name="snap.json"):
    path = tmp_path / name
    path.write_bytes(to_bytes(snap))
    return path


@pytest.fixture
def positive_file(tmp_path, positive_snapshot):
    return _file(tmp_path, positive_snapshot)


def test_host_is_listed_with_its_version_mode_and_target_type():
    result = runner.invoke(app, ["list", "--format", "json"])
    assert result.exit_code == 0
    host = next(s for s in json.loads(result.stdout) if s["name"] == "host")
    assert host == {
        "name": "host",
        "version": "0.1.0",
        "modes": ["light"],
        "target_types": ["host"],
    }
    table = runner.invoke(app, ["list"]).stdout
    assert any(
        line.startswith("host ") and "0.1.0" in line and "light" in line
        for line in table.splitlines()
    )


def test_scan_run_host_emits_the_findings(positive_file):
    result = runner.invoke(
        app,
        [
            "run",
            "host",
            "--target",
            "lab-vm-1",
            "--snapshot",
            str(positive_file),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["scanner"] == "host" and data["target"] == {
        "type": "host",
        "value": "lab-vm-1",
        "addresses": [],
    }
    by_check = {f["check_id"]: f for f in data["findings"]}
    assert set(by_check) == {"host-ssh-root-login", "host-kernel-reboot-pending"}
    assert by_check["host-kernel-reboot-pending"]["state"] == "highly_likely"
    assert by_check["host-ssh-root-login"]["state"] == "suspected"
    assert all(f["vantage"] == "agent" and f["engagement"] == "defensive" for f in data["findings"])
    assert data["outcome"] == "succeeded"


def test_scan_run_host_table_output(positive_file):
    result = runner.invoke(
        app, ["run", "host", "--target", "lab-vm-1", "--snapshot", str(positive_file)]
    )
    assert result.exit_code == 0
    assert "host-ssh-root-login" in result.stdout and "host-kernel-reboot-pending" in result.stdout


def test_a_clean_snapshot_has_no_findings_and_accounts_for_both_checks(tmp_path, clean_snapshot):
    path = _file(tmp_path, clean_snapshot)
    result = runner.invoke(
        app, ["run", "host", "--target", "lab-vm-1", "--snapshot", str(path), "--format", "json"]
    )
    data = json.loads(result.stdout)
    assert data["findings"] == []
    assert {c["check_id"]: c["outcome"] for c in data["telemetry"]["checks_run"]} == {
        "host-ssh-root-login": "clear",
        "host-kernel-reboot-pending": "clear",
    }


def test_fail_on_counts_only_claims_we_make(positive_file):
    """highly_likely (the reboot check) is a claim; the single-method ssh `suspected` is not."""
    base = ["run", "host", "--target", "lab-vm-1", "--snapshot", str(positive_file)]
    assert runner.invoke(app, [*base, "--fail-on", "low"]).exit_code == 2
    assert runner.invoke(app, [*base, "--fail-on", "high"]).exit_code == 0


def test_a_corrupted_snapshot_is_a_scan_error_that_exits_nonzero(tmp_path, positive_snapshot):
    positive_snapshot["sections"]["ssh"]["permitrootlogin"] = "no"  # edited after sealing
    path = _file(tmp_path, positive_snapshot)
    result = runner.invoke(
        app, ["run", "host", "--target", "lab-vm-1", "--snapshot", str(path), "--format", "json"]
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["outcome"] == "errored" and data["findings"] == []
    assert "self_hash" in data["errors"][0]["message"] and data["errors"][0]["fatal"] is True


def test_a_missing_snapshot_file_exits_nonzero(tmp_path):
    result = runner.invoke(
        app, ["run", "host", "--target", "x", "--snapshot", str(tmp_path / "nope.json")]
    )
    assert result.exit_code == 1
    assert "snapshot" in result.stdout


def test_host_without_a_snapshot_is_refused(positive_file):
    result = runner.invoke(app, ["run", "host", "--target", "lab-vm-1"])
    assert result.exit_code == 1
    assert "--snapshot" in result.stdout


def test_snapshot_flag_is_refused_for_a_scanner_that_does_not_take_one(positive_file):
    result = runner.invoke(
        app, ["run", "example", "--target", "example.com", "--snapshot", str(positive_file)]
    )
    assert result.exit_code == 1
    assert "does not take a snapshot" in result.stdout


def test_host_defaults_to_a_host_target_so_no_target_type_is_needed():
    result = runner.invoke(app, ["run", "host", "--target", "example.com"])
    assert (
        result.exit_code == 1
    )  # host target type, no snapshot: refused for the snapshot, not the type
    assert "--snapshot" in result.stdout


def test_a_target_that_is_not_the_snapshots_host_is_reported(tmp_path, positive_snapshot):
    path = _file(tmp_path, positive_snapshot)
    result = runner.invoke(
        app, ["run", "host", "--target", "other-box", "--snapshot", str(path), "--format", "json"]
    )
    data = json.loads(result.stdout)
    assert data["outcome"] == "partial"
    assert "lab-vm-1" in data["errors"][0]["message"] and data["errors"][0]["fatal"] is False


def test_terminal_output_never_carries_a_raw_escape_from_the_snapshot(tmp_path):
    snap = make_snapshot(packages=[PKG_OLD, PKG_NEW], root_login="yes")
    snap["sections"]["kernel"]["running_version_string"] = (
        "Linux 6.8.0-90-generic \x1b[2J\x1b]0;pwned\x07"
    )
    path = _file(tmp_path, rehash(snap))
    for fmt in ("table", "json"):
        result = runner.invoke(
            app,
            ["run", "host", "--target", "lab-vm-1", "--snapshot", str(path), "--format", fmt],
        )
        assert result.exit_code == 0
        assert "\x1b" not in result.stdout and "\x07" not in result.stdout


def test_an_unsupported_runtime_snapshot_is_unassessed_in_the_cli(tmp_path):
    from agent import snapshot as agent_snapshot
    from agent.__main__ import unsupported_snapshot

    snap = unsupported_snapshot("2.7.18", "/usr/bin/python")
    snap["host"]["hostname"] = "old-box"
    snap["self_hash"] = agent_snapshot.compute_hash(snap)
    path = _file(tmp_path, snap)
    result = runner.invoke(
        app, ["run", "host", "--target", "old-box", "--snapshot", str(path), "--format", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert {f["state"] for f in data["findings"]} == {"inconclusive"}
    assert all("unassessed" in f["description"] for f in data["findings"])
