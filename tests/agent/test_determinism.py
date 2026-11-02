"""E2: two runs against the same fake host differ only in time. Whole-snapshot version.

Masked: collected_at, the clock block (incl. monotonic), receipt start/finish, every
duration_ms, and the self_hash that covers them. Everything else must be byte-identical.
"""

import copy

from agent import collect, snapshot
from tests.agent.test_minimisation import _plant


def _mask(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in ("collected_at", "clock", "self_hash", "started_at", "finished_at"):
                out[k] = None
            elif k.endswith("duration_ms") or k == "monotonic_ms":
                out[k] = 0
            else:
                out[k] = _mask(v)
        return out
    if isinstance(node, list):
        return [_mask(v) for v in node]
    return node


def _run(host, euid):
    receipt, runner, reader = host.tools(euid=euid)
    reader.read("/etc/shadow")
    runner.request(["cat", "/etc/shadow"])
    return collect.collect(receipt, runner, reader, hostname="web-1")


def _bytes(snap):
    return snapshot.dumps(_mask(copy.deepcopy(snap)))


def test_two_runs_are_byte_identical_once_time_is_masked(host):
    a, b = _run(host, 0), _run(host, 0)
    assert _bytes(a) == _bytes(b)


def test_determinism_holds_on_error_and_refusal_paths(host):
    _plant(host)
    host.set_command("sshd", "port 22\n", code=0)  # required key missing -> error section
    a, b = _run(host, 1000), _run(host, 1000)
    statuses = {m["status"] for m in a["manifest"]}
    assert "error" in statuses or "unavailable" in statuses
    assert _bytes(a) == _bytes(b)


def test_the_mask_is_not_hiding_a_real_difference(host):
    a = _run(host, 0)
    host.set_command("uname", "Linux 6.8.0-100-generic #1 SMP x86_64\n")
    b = _run(host, 0)
    assert _bytes(a) != _bytes(b)
