"""ssh: selected keys of the EFFECTIVE sshd configuration (`sshd -T`).

Only the keys named here are kept; the rest of the output (host key paths, banners,
listen addresses) is dropped at parse time. Needs root; without it the section is
unavailable, not guessed from the config files.
"""

from typing import Dict

from agent import modules
from agent.modules import Outcome
from agent.readfile import FileReader
from agent.run import Runner

KEYS = ("permitrootlogin", "passwordauthentication", "x11forwarding", "permitemptypasswords")
REQUIRED = ("permitrootlogin",)


def collect(runner: Runner, reader: FileReader) -> Outcome:
    res = runner.run(modules.command(runner, "ssh.effective"))
    if res.status == "missing_binary" and res.refused_because == "binary_not_found":
        return modules.unavailable("sshd_not_installed")
    problem = modules.command_problem(res)
    if problem:
        return problem
    if res.exit_status != 0:
        return modules.failed("command_failed:%s:%s" % (res.reason_id, res.exit_status))
    found: Dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() in KEYS and parts[0].lower() not in found:
            found[parts[0].lower()] = parts[1].strip()
    for key in REQUIRED:
        if key not in found:
            return modules.failed("key_missing_from_output:%s" % key)
    body: Dict[str, str] = {"source": "sshd -T"}
    body.update(found)
    return modules.collected(body)
