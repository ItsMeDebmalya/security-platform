"""packages: installed package names and versions, nothing else.

No advisory data is consulted here. Entries with no version (removed, config left)
are not installed and are skipped.
"""

from typing import Dict, List

from agent import modules
from agent.modules import Outcome
from agent.readfile import FileReader
from agent.run import Runner


def collect(runner: Runner, reader: FileReader) -> Outcome:
    res = runner.run(modules.command(runner, "packages.debian"))
    if res.status == "missing_binary" and res.refused_because == "binary_not_found":
        return modules.unavailable("package_manager_unsupported")
    problem = modules.command_problem(res)
    if problem:
        return problem
    items: List[Dict[str, str]] = []
    for line in res.stdout.splitlines():
        name, _, ver = line.partition("\t")
        if name and ver.strip():
            items.append({"name": name, "version": ver.strip()})
    items.sort(key=lambda i: (i["name"], i["version"]))
    return modules.collected({"manager": "dpkg", "items": items, "truncated": res.stdout_truncated})
