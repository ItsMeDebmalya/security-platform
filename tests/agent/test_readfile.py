"""C3: the allowlisted file reader."""

import os

import pytest

from agent import allowlist as al
from agent.readfile import FileReader, excluded, parse_keys
from agent.receipt import Receipt

SSHD = """# comment
PermitRootLogin no
passwordauthentication yes
Banner /etc/issue
PermitRootLogin yes
Match User bob
    X11Forwarding yes
"""


def fentry(
    path,
    keys=("PermitRootLogin", "PasswordAuthentication", "X11Forwarding"),
    fmt="space",
    cap=10000,
    rid="t.file",
):
    return al.FileEntry(rid, str(path), "test", "test", keys, fmt, cap)


def mk(entry, excludes=al.EXCLUDED):
    r = Receipt(euid=os.geteuid())
    return r, FileReader(r, files=[entry], excludes=excludes)


def test_key_extraction_only_first_wins_stops_at_match(tmp_path):
    p = tmp_path / "sshd_config"
    p.write_text(SSHD)
    e = fentry(p)
    r, rd = mk(e)
    [res] = rd.read_entry(e)
    assert res.values == {"PermitRootLogin": "no", "PasswordAuthentication": "yes"}
    rec = r.files[0]
    assert rec["keys_extracted"] == ["PasswordAuthentication", "PermitRootLogin"]
    assert (
        "Banner" not in str(rec)
        and "/etc/issue" not in str(rec)
        and "no" not in rec["keys_extracted"]
    )
    assert rec["reason_id"] == "t.file" and rec["bytes_read"] == len(SSHD)


def test_equals_format():
    assert parse_keys(
        'ID=ubuntu\nVERSION_ID="22.04"\nHOME_URL=x\n', ("ID", "VERSION_ID"), "equals"
    ) == {"ID": "ubuntu", "VERSION_ID": "22.04"}


def test_symlink_refused(tmp_path):
    target = tmp_path / "real"
    target.write_text("PermitRootLogin no\n")
    link = tmp_path / "link"
    os.symlink(target, link)
    e = fentry(link)
    r, rd = mk(e)
    [res] = rd.read_entry(e)
    assert res.status == "refused" and res.refused_because == "symlink"
    assert r.files_refused[0]["refused_because"] == "symlink" and r.files == []


def test_fifo_refused_without_blocking(tmp_path):
    p = tmp_path / "fifo"
    os.mkfifo(p)
    e = fentry(p)
    _, rd = mk(e)
    [res] = rd.read_entry(e)
    assert res.refused_because == "not_regular_file"


def test_foreign_owner_refused(tmp_path):
    p = tmp_path / "f"
    p.write_text("PermitRootLogin no\n")
    e = fentry(p)
    r = Receipt(euid=os.geteuid() + 4242)  # neither root nor the file's owner
    if os.geteuid() == 0:
        pytest.skip("root owns it; owner check covered by uid in (0, euid)")
    rd = FileReader(r, files=[e])
    assert rd.read_entry(e)[0].refused_because == "bad_owner"


def test_truncation_recorded(tmp_path):
    p = tmp_path / "big"
    p.write_text("PermitRootLogin no\n" + "x" * 5000)
    e = fentry(p, cap=100)
    r, rd = mk(e)
    [res] = rd.read_entry(e)
    assert res.truncated and res.bytes_read == 100 and r.files[0]["truncated"] is True


def test_absent_is_recorded_not_a_refusal(tmp_path):
    e = fentry(tmp_path / "nope")
    r, rd = mk(e)
    assert rd.read_entry(e)[0].status == "absent"
    assert r.files[0]["present"] is False and r.files_refused == []


def test_not_in_allowlist_and_exclusions_refused(tmp_path):
    e = fentry(tmp_path / "a")
    r, rd = mk(e)
    assert rd.read("/etc/passwd").refused_because == "not_in_allowlist"
    assert rd.read("/etc/shadow").refused_because == "excluded_by_allowlist"
    assert rd.read("/etc/ssh/ssh_host_ed25519_key").refused_because == "excluded_private_key"
    assert rd.read("/home/u/.ssh/id_rsa").refused_because == "excluded_by_allowlist"
    assert [x["path"] for x in r.files_refused] == [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/ssh_host_ed25519_key",
        "/home/u/.ssh/id_rsa",
    ]


def test_exclusion_beats_allowlist(tmp_path):
    p = tmp_path / "server.key"
    p.write_text("PermitRootLogin no\n")
    e = fentry(p)
    _, rd = mk(e)
    assert rd.read_entry(e)[0].refused_because == "excluded_private_key"


def test_pattern_entry_reads_each_match_and_skips_others(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.conf").write_text("PermitRootLogin no\n")
    (d / "b.conf").write_text("X11Forwarding yes\n")
    (d / "c.txt").write_text("PermitRootLogin yes\n")
    e = fentry(d / "*.conf")
    _, rd = mk(e)
    res = rd.read_entry(e)
    assert [x.path for x in res] == [str(d / "a.conf"), str(d / "b.conf")]
    assert rd.read(str(d / "c.txt")).refused_because == "not_in_allowlist"


def test_excluded_helper():
    assert excluded("/etc/ok") is None
