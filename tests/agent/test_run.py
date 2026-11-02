"""C2: the runner, against fake binaries in a temp 'bin dir'."""

import os
import stat

import pytest

from agent import allowlist as al
from agent.receipt import Receipt
from agent.run import Runner, environment, resolve_binary


def fake(dirpath, name, script):
    p = dirpath / name
    p.write_text("#!/bin/sh\n" + script + "\n")
    p.chmod(0o755)
    return p


def entry(name="fake", args=(), rid="t.fake", timeout=5, cap=1000, root=False, nz=False):
    return al.CommandEntry(rid, (name, *args), "test", ("x",), timeout, cap, root, nz)


@pytest.fixture
def bindir(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    return d


def mk(bindir, e, euid=1000):
    r = Receipt(euid=euid)
    return r, Runner(r, commands=[e], bin_dirs=[str(bindir)])


def test_success_captured_and_recorded(bindir):
    fake(bindir, "fake", "echo hello; echo err >&2")
    e = entry()
    r, run = mk(bindir, e)
    res = run.run(e)
    assert res.status == "ran" and res.exit_status == 0 and res.stdout == "hello\n"
    assert res.stderr_bytes == 4 and not res.stdout_truncated and not res.failed
    rec = r.to_dict()["commands"]
    assert len(rec) == 1 and rec[0]["reason_id"] == "t.fake" and rec[0]["exit_status"] == 0


def test_nonzero_exit_recorded_and_failed_unless_expected(bindir):
    fake(bindir, "fake", "exit 3")
    e = entry()
    r, run = mk(bindir, e)
    res = run.run(e)
    assert res.exit_status == 3 and res.failed
    assert r.counts()["commands_failed"] == 1
    e2 = entry(nz=True)
    _, run2 = mk(bindir, e2)
    assert not run2.run(e2).failed


def test_timeout_kills_and_records(bindir):
    fake(bindir, "fake", "/bin/sleep 30")
    e = entry(timeout=0.5)
    r, run = mk(bindir, e)
    res = run.run(e)
    assert res.status == "timeout" and res.failed and res.duration_ms < 10000
    assert r.commands[0]["status"] == "timeout"


def test_missing_binary_recorded(bindir):
    e = entry(name="nosuch")
    r, run = mk(bindir, e)
    res = run.run(e)
    assert res.status == "missing_binary" and res.failed
    assert r.commands[0]["problem"] == "binary_not_found"


def test_oversized_output_truncated_and_recorded(bindir):
    fake(bindir, "fake", "/usr/bin/head -c 100000 /dev/zero | /usr/bin/tr '\\0' a")
    e = entry(cap=1000)
    r, run = mk(bindir, e)
    res = run.run(e)
    assert len(res.stdout) == 1000 and res.stdout_truncated and res.stdout_bytes == 100000
    assert r.commands[0]["stdout_truncated"] is True


def test_refusal_not_in_allowlist(bindir):
    fake(bindir, "fake", "echo hi")
    r, run = mk(bindir, entry())
    res = run.request(["fake", "--evil"])
    assert res.status == "refused" and res.refused_because == "not_in_allowlist"
    assert r.commands == [] and r.commands_refused[0]["argv_requested"] == ["fake", "--evil"]
    assert run.run(entry(name="other")).status == "refused"


def test_request_exact_match_runs(bindir):
    fake(bindir, "fake", "echo hi")
    _, run = mk(bindir, entry())
    assert run.request(["fake"]).status == "ran"


def test_needs_root_refused_when_unprivileged(bindir):
    fake(bindir, "fake", "echo hi")
    e = entry(root=True)
    r, run = mk(bindir, e, euid=1000)
    assert run.run(e).refused_because == "needs_root" and r.commands == []
    _, run0 = mk(bindir, e, euid=0)
    assert run0.run(e).status == "ran"


def test_symlink_out_of_dirs_refused(bindir, tmp_path):
    outside = tmp_path / "evil"
    outside.write_text("#!/bin/sh\necho pwned\n")
    outside.chmod(0o755)
    os.symlink(outside, bindir / "fake")
    assert resolve_binary("fake", [str(bindir)]) == (None, "binary_unsafe")
    e = entry()
    r, run = mk(bindir, e)
    assert run.run(e).status == "missing_binary"
    assert r.commands[0]["problem"] == "binary_unsafe"


def test_symlink_within_dirs_ok(bindir):
    real = fake(bindir, "real", "echo ok")
    os.symlink(real, bindir / "fake")
    path, why = resolve_binary("fake", [str(bindir)])
    assert why is None and path == str(real.resolve())


def test_non_executable_and_path_traversal_names(bindir):
    p = bindir / "fake"
    p.write_text("x")
    p.chmod(stat.S_IRUSR)
    assert resolve_binary("fake", [str(bindir)])[1] == "binary_unsafe"
    assert resolve_binary("../x", [str(bindir)])[1] == "binary_unsafe"


def test_path_is_not_consulted(bindir, tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    fake(other, "fake", "echo from-path")
    monkeypatch.setenv("PATH", str(other))
    assert resolve_binary("fake", [str(bindir)]) == (None, "binary_not_found")


def test_env_is_scrubbed(bindir, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "hunter2")
    fake(bindir, "fake", "/usr/bin/env")
    e = entry()
    _, run = mk(bindir, e)
    out = run.run(e).stdout
    assert "SECRET_TOKEN" not in out and "LC_ALL=C" in out and "TZ=UTC" in out
    assert environment(["/a", "/b"])["PATH"] == "/a:/b"


def test_shell_metacharacters_are_inert(bindir, tmp_path):
    marker = tmp_path / "marker"
    fake(bindir, "fake", 'echo "$1"')
    e = entry(args=(f"; touch {marker}",))
    _, run = mk(bindir, e)
    res = run.run(e)
    assert res.stdout.startswith("; touch") and not marker.exists()
