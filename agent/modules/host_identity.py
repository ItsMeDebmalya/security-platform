"""host_identity: the hostname and a one-way fingerprint of the machine id.

The raw machine id is never stored: it is read, hashed with a fixed label, and dropped.
"""

import hashlib
import socket
from typing import Optional

from agent import modules
from agent.modules import Outcome
from agent.readfile import FileReader
from agent.run import Runner

LABEL = "security-platform/host-fingerprint:"


def fingerprint(machine_id: str) -> str:
    digest = hashlib.sha256((LABEL + machine_id).encode("utf-8")).hexdigest()
    return "sha256:" + digest[:16]


def collect(runner: Runner, reader: FileReader, hostname: Optional[str] = None) -> Outcome:
    res = reader.read_entry(modules.file_entry(reader, "host.machine_id"))[0]
    raw = res.values.get("machine_id") if res.status == "read" else None
    return modules.collected(
        {
            "hostname": hostname if hostname is not None else socket.gethostname(),
            "machine_id_fingerprint": fingerprint(raw) if raw else None,
        }
    )
