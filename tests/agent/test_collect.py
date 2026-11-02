"""The orchestrator: modules -> sections -> manifest -> redact -> receipt -> file."""

import copy
import json
import os
import subprocess
import sys

from agent import collect, snapshot, version

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(host, euid=0):
    receipt, runner, reader = host.tools(euid=euid)
    return collect.collect(receipt, runner, reader, hostname="web-1")


def by_section(snap):
    return {m["section"]: m for m in snap["manifest"]}


def test_full_snapshot(host):
    snap = run(host)
    assert snapshot.verify(snap)
    assert [m["section"] for m in snap["manifest"]] == list(version.SECTIONS)
    assert all(m["status"] == "collected" for m in snap["manifest"])
    assert set(snap["sections"]) == set(version.SECTIONS)
    assert snap["sections"]["kernel"]["running_release"] == "6.8.0-90-generic"
    assert snap["host"]["hostname"] == "web-1"
    assert snap["counts"]["sections_collected"] == len(version.SECTIONS)
    assert snap["counts"]["commands_run"] == 3 and snap["counts"]["commands_failed"] == 0


def test_receipt_is_inside_the_snapshot(host):
    snap = run(host)
    rec = snap["receipt"]
    assert {c["reason_id"] for c in rec["commands"]} == {
        "kernel.uname",
        "packages.debian",
        "ssh.effective",
    }
    assert any(f["reason_id"] == "os.release" and f["present"] for f in rec["files"])


def test_command_failure_is_an_error_section_not_a_pass(host):
    host.set_command("sshd", "", code=255)
    snap = run(host)
    m = by_section(snap)
    assert m["ssh"]["status"] == "error" and "255" in m["ssh"]["error"]
    assert "ssh" not in snap["sections"]
    assert snap["counts"]["sections_error"] == 1
    assert m["kernel"]["status"] == "collected"


def test_needs_root_refusal_is_unavailable(host):
    snap = run(host, euid=1000)
    m = by_section(snap)
    assert m["ssh"] == {"section": "ssh", "status": "unavailable", "reason": "needs_root"}
    assert snap["counts"]["commands_refused"] == 1
    assert snap["receipt"]["commands_refused"][0]["refused_because"] == "needs_root"


def test_absent_file_is_unavailable_with_reason(host):
    host.remove("/etc/os-release")
    m = by_section(run(host))
    assert m["os_release"]["status"] == "unavailable" and m["os_release"]["reason"] == "file_absent"


def test_a_module_that_raises_becomes_an_error_section(host, monkeypatch):
    def boom(runner, reader):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(collect.packages, "collect", boom)
    m = by_section(run(host))
    assert m["packages"]["status"] == "error"
    assert m["packages"]["error"] == "module_exception:RuntimeError"


def test_secrets_in_section_values_are_redacted_at_assembly(host):
    token = "ghp_" + "a" * 30
    host.set_command("sshd", "permitrootlogin yes\nx11forwarding " + token + "\n")
    snap = run(host)
    text = json.dumps(snap)
    assert token not in text
    assert snap["sections"]["ssh"]["x11forwarding"].startswith("[redacted")
    assert snap["receipt"]["redactions"] == {"github_token": 1}
    assert snapshot.verify(snap)


def test_receipt_refusal_strings_are_redacted_too(host):
    token = "ghp_" + "b" * 30
    receipt, runner, reader = host.tools(euid=0)
    reader.read("/tmp/" + token)  # a caller-supplied path lands in files_refused
    snap = collect.collect(receipt, runner, reader, hostname="h")
    assert token not in json.dumps(snap)


MASK = ("collected_at", "clock", "self_hash")


def _masked(snap):
    s = copy.deepcopy(snap)
    for k in MASK:
        s[k] = None
    for key in ("started_at", "finished_at"):
        s["receipt"][key] = None
    for c in s["receipt"]["commands"]:
        c["duration_ms"] = 0
    return s


def test_determinism_two_runs_differ_only_in_timestamps(host):
    a, b = run(host), run(host)
    assert _masked(a) == _masked(b)


def test_main_writes_the_named_file(host, tmp_path):
    out = tmp_path / "snap.json"
    rc = collect.main(["--output", str(out)], tools=lambda: host.tools(euid=0))
    assert rc == 0
    snap = json.loads(out.read_text())
    assert snapshot.verify(snap) and out.read_text().endswith("\n")
    assert (os.stat(str(out)).st_mode & 0o777) == 0o600


def test_main_requires_an_output_path(host, capsys):
    assert collect.main([], tools=lambda: host.tools()) == 2
    assert "--output" in capsys.readouterr().err


def test_main_unwritable_path_fails_loudly(host, tmp_path):
    rc = collect.main(
        ["--output", str(tmp_path / "no" / "dir" / "s.json")], tools=lambda: host.tools()
    )
    assert rc == 1


def test_shim_runs_the_real_collector_on_a_supported_runtime(tmp_path):
    out = tmp_path / "s.json"
    proc = subprocess.run(
        [sys.executable, "-m", "agent", "--output", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    snap = json.loads(out.read_text())
    assert snapshot.verify(snap)
    assert [m["section"] for m in snap["manifest"]] == list(version.SECTIONS)
