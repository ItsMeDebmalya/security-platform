"""A fake host for the collection-module tests: fake binaries in a temp bin dir and
allowlist file entries re-pointed at a temp tree. Nothing here touches the real host."""

import os
import shlex

import pytest

from agent import allowlist
from agent.readfile import FileReader
from agent.receipt import Receipt
from agent.run import Runner

UNAME = "Linux 6.8.0-90-generic #101-Ubuntu SMP PREEMPT_DYNAMIC Mon Oct  6 12:00:00 UTC 2025 x86_64"
OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
DPKG = (
    "bash\t5.2.21-2ubuntu4\n"
    "linux-image-6.8.0-90-generic\t6.8.0-90.101\n"
    "linux-image-6.8.0-100-generic\t6.8.0-100.110\n"
    "ghost\t\n"
)
SSHD_T = "port 22\npermitrootlogin yes\npasswordauthentication no\nx11forwarding no\n"
MACHINE_ID = "0123456789abcdef0123456789abcdef\n"


class FakeHost:
    def __init__(self, root):
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        (root / "out").mkdir()
        self.set_command("uname", UNAME + "\n")
        self.set_command("dpkg-query", DPKG)
        self.set_command("sshd", SSHD_T)
        self.write("/etc/os-release", OS_RELEASE)
        self.write("/etc/machine-id", MACHINE_ID)
        self.files = tuple(e._replace(path=str(root) + e.path) for e in allowlist.FILES)

    def set_command(self, name, stdout, code=0):
        data = self.root / "out" / name
        data.write_text(stdout)
        script = self.bin / name
        script.write_text(f"#!/bin/sh\n/bin/cat {shlex.quote(str(data))}\nexit {code}\n")
        script.chmod(0o755)

    def remove_command(self, name):
        (self.bin / name).unlink()

    def write(self, path, text):
        p = self.root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def remove(self, path):
        (self.root / path.lstrip("/")).unlink()

    def tools(self, euid=None):
        euid = os.geteuid() if euid is None else euid
        receipt = Receipt(euid=euid)
        runner = Runner(receipt, bin_dirs=[str(self.bin)])
        reader = FileReader(receipt, files=self.files)
        return receipt, runner, reader


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path)
