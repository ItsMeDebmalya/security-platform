"""Synthetic host snapshots for the `host` scanner's unit tests.

Built with the collector's own `agent.snapshot` helpers, so the shape and the self-hash are
the real ones; the *content* is hand-written. Recorded lab snapshots replace these in the
corpus (Task 8) - a synthetic snapshot proves the code path, not that the world looks like this.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from agent import snapshot as agent_snapshot

HOST_REF = "sha256:474cbba19098a942"
HOSTNAME = "lab-vm-1"
RUNNING = "6.8.0-90-generic"

PKG_OLD = {"name": "linux-image-6.8.0-90-generic", "version": "6.8.0-90.91"}
PKG_NEW = {"name": "linux-image-6.8.0-94-generic", "version": "6.8.0-94.96"}
PKG_META = {"name": "linux-image-generic", "version": "6.8.0-94.96"}
PKG_OTHER = {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5"}


def _command(reason_id: str, argv: list[str], stdout_bytes: int) -> dict[str, Any]:
    return {
        "argv": argv,
        "duration_ms": 3,
        "exit_status": 0,
        "failed": False,
        "reason_id": reason_id,
        "read_for": [],
        "status": "ran",
        "stderr_bytes": 0,
        "stdout_bytes": stdout_bytes,
        "stdout_truncated": False,
    }


def make_snapshot(
    *,
    packages: list[dict[str, str]] | None = None,
    root_login: str = "prohibit-password",
    ownership: str = "own",
    running: str = RUNNING,
    ssh: str = "collected",
    hostname: str = HOSTNAME,
    fingerprint: str | None = HOST_REF,
) -> dict[str, Any]:
    packages = copy.deepcopy([PKG_OLD, PKG_OTHER] if packages is None else packages)
    manifest = [
        agent_snapshot.entry("os_release", "unavailable", reason="symlink"),
        agent_snapshot.entry("kernel", "collected"),
        agent_snapshot.entry("host_identity", "collected"),
        agent_snapshot.entry("packages", "collected"),
    ]
    sections: dict[str, Any] = {
        "kernel": {
            "architecture": "x86_64",
            "kernel_ownership": ownership,
            "ownership_basis": ["container.dockerenv"] if ownership == "shared" else [],
            "running_release": running,
            "running_version_string": f"Linux {running} #91-Ubuntu SMP x86_64",
        },
        "host_identity": {"hostname": hostname, "machine_id_fingerprint": fingerprint},
        "packages": {"manager": "dpkg", "items": packages, "truncated": False},
    }
    if ssh == "collected":
        manifest.append(agent_snapshot.entry("ssh", "collected"))
        sections["ssh"] = {
            "source": "sshd -T",
            "permitrootlogin": root_login,
            "passwordauthentication": "no",
        }
    elif ssh == "error":
        manifest.append(
            agent_snapshot.entry("ssh", "error", error="command_failed:ssh.effective:255")
        )
    else:
        manifest.append(agent_snapshot.entry("ssh", "unavailable", reason="needs_root"))
    receipt = {
        "receipt_version": 1,
        "collector_version": "0.1.0",
        "effective_uid": 0,
        "effective_user": "root",
        "started_at": "2026-10-29T09:50:03Z",
        "finished_at": "2026-10-29T09:50:04Z",
        "commands": [
            _command("kernel.uname", ["/usr/bin/uname", "-srvm"], 90),
            _command(
                "packages.debian",
                ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                32035,
            ),
        ]
        + (
            [_command("ssh.effective", ["/usr/sbin/sshd", "-T"], 4406)]
            if ssh != "needs_root"
            else []
        ),
        "commands_refused": [],
        "files": [],
        "files_refused": [],
        "redactions": {},
    }
    return agent_snapshot.build(
        manifest,
        sections,
        {"commands_run": len(receipt["commands"])},
        host={"hostname": hostname, "machine_id_fingerprint": fingerprint},
        collected_at="2026-10-29T09:50:04Z",
        clock={"source": "host", "tz_offset_minutes": 330, "monotonic_ms": 1000},
        receipt=receipt,
    )


def rehash(snap: dict[str, Any]) -> dict[str, Any]:
    """Re-seal a hand-edited snapshot so a test reaches the field it is about."""
    snap["self_hash"] = agent_snapshot.compute_hash(snap)
    return snap


def to_bytes(snap: dict[str, Any]) -> bytes:
    return json.dumps(snap, sort_keys=True).encode("utf-8")


def edited(snap: dict[str, Any], mutate) -> dict[str, Any]:
    out = copy.deepcopy(snap)
    mutate(out)
    return rehash(out)


def assess(snap: dict[str, Any]):
    """The ScanResult for a synthetic snapshot, through the real reader."""
    from scanners.host.scanner import HostScanner

    from scanners.host import reader

    return HostScanner().assess(reader.parse(to_bytes(snap)))


def run_host_check(check_id: str, snap: dict[str, Any]):
    """The finding `check_id` produced, or None when it ran and found nothing wrong."""
    result = assess(snap)
    ran = [c for c in result.telemetry.checks_run if c.check_id == check_id]
    assert len(ran) == 1, "every check accounts for having run, exactly once"
    found = [f for f in result.findings if f.check_id == check_id]
    assert bool(found) == (ran[0].outcome in {"reported", "inconclusive"})
    return found[0] if found else None


def outcome(check_id: str, snap: dict[str, Any]) -> str:
    return next(c.outcome for c in assess(snap).telemetry.checks_run if c.check_id == check_id)
