"""C4: the receipt is assembled as commands and files run."""

import os

from agent import allowlist as al
from agent.readfile import FileReader
from agent.receipt import Receipt
from agent.run import Runner
from agent.snapshot import COUNT_FIELDS


def test_everything_that_ran_appears_once_and_every_refusal_appears(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("one", "two"):
        p = bindir / name
        p.write_text(f"#!/bin/sh\necho {name}\n")
        p.chmod(0o755)
    c1 = al.CommandEntry("c.one", ("one",), "t", ("a",), 5, 100)
    c2 = al.CommandEntry("c.two", ("two",), "t", ("b",), 5, 100)
    f = tmp_path / "conf"
    f.write_text("PermitRootLogin no\n")
    f1 = al.FileEntry("f.conf", str(f), "t", "t", ("PermitRootLogin",), "space", 1000)
    r = Receipt(euid=os.geteuid(), collector_version="0.1.0")
    run = Runner(r, commands=[c1, c2], bin_dirs=[str(bindir)])
    rd = FileReader(r, files=[f1])
    run.run(c1)
    run.run(c2)
    run.request(["rm", "-rf", "/"])
    rd.read_entry(f1)
    rd.read("/etc/shadow")
    d = r.to_dict()
    assert [c["reason_id"] for c in d["commands"]] == ["c.one", "c.two"]
    assert [x["reason_id"] for x in d["files"]] == ["f.conf"]
    assert d["commands_refused"][0]["argv_requested"] == ["rm", "-rf", "/"]
    assert d["files_refused"][0]["path"] == "/etc/shadow"
    assert d["receipt_version"] == 1 and d["effective_uid"] == os.geteuid()
    assert d["commands"][0]["argv"][0] == str(bindir / "one")


def test_counts_use_snapshot_names_and_each_says_what_it_counted():
    r = Receipt(euid=1000)
    r.add_command({"failed": False})
    r.add_command({"failed": True})
    r.add_command_refusal({})
    r.add_file({"present": True, "bytes_read": 7})
    r.add_file({"present": False, "bytes_read": 0})
    r.add_file_refusal({})
    c = r.counts()
    assert set(c) <= set(COUNT_FIELDS)
    assert c == {
        "commands_run": 2,
        "commands_refused": 1,
        "commands_failed": 1,
        "files_read": 1,
        "files_refused": 1,
        "bytes_read": 7,
    }
