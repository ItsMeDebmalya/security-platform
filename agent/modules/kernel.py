"""kernel: the RUNNING kernel, and whether the box owns it.

A container reports its host's kernel, so "which kernel is installed" is not a fact
about a container. `kernel_ownership` records what the markers show; the platform
decides what that means.
"""

from typing import List

from agent import modules
from agent.modules import Outcome
from agent.readfile import FileReader
from agent.run import Runner

MARKERS = ("container.dockerenv", "container.podman", "container.systemd")


def collect(runner: Runner, reader: FileReader) -> Outcome:
    res = runner.run(modules.command(runner, "kernel.uname"))
    problem = modules.command_problem(res)
    if problem:
        return problem
    line = res.stdout.strip()
    tokens = line.split()
    if len(tokens) < 3:
        return modules.failed("unparseable_uname")
    present: List[str] = []
    unreadable = False
    for reason_id in MARKERS:
        got = reader.read_entry(modules.file_entry(reader, reason_id))[0]
        if got.status == "read":
            present.append(reason_id)
        elif got.status != "absent":
            unreadable = True
    if present:
        ownership = "shared"
    elif unreadable:
        ownership = "unknown"
    else:
        ownership = "own"
    return modules.collected(
        {
            "running_release": tokens[1],
            "running_version_string": line,
            "architecture": tokens[-1],
            "kernel_ownership": ownership,
            "ownership_basis": present,
        }
    )
