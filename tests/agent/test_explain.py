"""E3 (--explain, after the fact) and E4 (--explain-plan, before it runs).

E4 executes nothing: subprocess and every file open are seams that fail the test if
touched, and every allowlist entry and exclusion must appear in the printed plan so it
cannot drift from the enforced one.
"""

import builtins
import io
import json
import os
import subprocess
import sys

import pytest

from agent import allowlist, collect, explain, snapshot


def _esc(s):
    return json.dumps(s)[1:-1]


# ---- E4 ------------------------------------------------------------------------------


@pytest.fixture
def no_exec_no_open(monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"--explain-plan touched the host: {a[:1]!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, boom)
    for name in ("system", "popen", "execv", "execvp", "spawnv", "posix_spawn", "open", "listdir"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, boom)
    monkeypatch.setattr(builtins, "open", boom)
    monkeypatch.setattr(io, "open", boom)


def test_plan_executes_nothing_and_opens_nothing(no_exec_no_open, capsys):
    rc = collect.main(["--explain-plan"])
    assert rc == 0
    assert capsys.readouterr().out.strip()


def test_plan_needs_no_output_path_and_no_root(no_exec_no_open, capsys, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert collect.main(["--explain-plan"]) == 0


def test_every_command_is_in_the_plan_with_all_its_fields(no_exec_no_open):
    text = explain.render_plan()
    for c in allowlist.COMMANDS:
        assert c.reason_id in text
        assert c.reason in text
        for a in c.argv:
            assert _esc(a) in text
        assert f"{c.timeout_s:g}" in text
        assert str(c.max_bytes) in text
    assert text.count("needs root: yes") == sum(1 for c in allowlist.COMMANDS if c.needs_root)
    assert text.count("needs root: no") == sum(1 for c in allowlist.COMMANDS if not c.needs_root)


def test_every_file_is_in_the_plan_with_its_keys(no_exec_no_open):
    text = explain.render_plan()
    for f in allowlist.FILES:
        assert f.reason_id in text and f.path in text
        assert f.reason in text and f.judged_from in text
        for k in f.keys:
            assert k in text


def test_every_exclusion_is_listed_explicitly(no_exec_no_open):
    text = explain.render_plan()
    for pattern, code, why in allowlist.EXCLUDED:
        assert pattern in text and code in text and why in text
    for must in ("/etc/shadow", ".ssh", ".env", ".aws"):
        assert must in text


def test_plan_follows_the_enforced_lists_not_a_copy(no_exec_no_open):
    extra = allowlist.CommandEntry("x.new", ("true",), "A new thing.", ("x",), 3, 99)
    text = explain.render_plan(commands=(*allowlist.COMMANDS, extra))
    assert "x.new" in text and "A new thing." in text


def test_plan_states_it_ran_nothing(no_exec_no_open):
    assert "nothing was run" in explain.render_plan().lower()


# ---- E3 ------------------------------------------------------------------------------


def _snap(host, euid=1000):
    receipt, runner, reader = host.tools(euid=euid)
    reader.read("/etc/shadow")
    runner.request(["cat", "/etc/shadow"])
    return collect.collect(receipt, runner, reader, hostname="web-1")


def test_explain_names_every_command_and_every_refusal(host):
    snap = _snap(host)
    rec = snap["receipt"]
    assert rec["commands"] and rec["commands_refused"] and rec["files_refused"]
    text = explain.render_receipt(rec)
    for c in rec["commands"]:
        assert c["reason_id"] in text
        assert all(_esc(a) in text for a in c["argv"])
    for c in rec["commands_refused"]:
        assert c["refused_because"] in text
        assert all(_esc(a) in text for a in c["argv_requested"])
    for f in rec["files"]:
        assert f["path"] in text
    for f in rec["files_refused"]:
        assert f["path"] in text and f["refused_because"] in text
    # in the owner's words, with the reason from the allowlist
    assert allowlist.COMMANDS[0].reason in text
    assert "ssh.effective" in text and "needs_root" in text


def test_explain_never_prints_collected_values(host):
    snap = _snap(host, euid=0)
    text = explain.render_receipt(snap["receipt"])
    assert "0123456789abcdef0123456789abcdef" not in text
    assert "Ubuntu" not in text


def test_explain_cli_reads_a_snapshot_file(host, tmp_path, capsys):
    snap = _snap(host)
    p = tmp_path / "s.json"
    p.write_text(snapshot.dumps(snap))
    assert collect.main(["--explain", str(p)]) == 0
    out = capsys.readouterr().out
    assert "ssh.effective" in out and "/etc/shadow" in out


def test_explain_cli_bad_file_is_an_error_not_a_crash(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert collect.main(["--explain", str(p)]) == 1
    assert collect.main(["--explain", str(tmp_path / "missing.json")]) == 1
    p.write_text(json.dumps({"no": "receipt"}))
    assert collect.main(["--explain", str(p)]) == 1


def test_module_entry_point_wires_the_flag():
    r = subprocess.run(
        [sys.executable, "-m", "agent", "--explain-plan"], capture_output=True, text=True
    )
    assert r.returncode == 0 and "kernel.uname" in r.stdout
