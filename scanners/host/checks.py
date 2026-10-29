"""The two Tier-B host checks, as pure functions of a validated snapshot (spec 9, F2, F3).

A check reads `collected` sections only. A section that is `error` or `unavailable`, a manifest
that does not mention it, a snapshot whose every section is `unsupported_runtime`: each is
INCONCLUSIVE, naming the reason, and never a pass (R1/R2). Nothing here judges from a value it
did not read from a collected section, and nothing here sets `state`: the scanner hands the
evidence to `core/state.py`.

Both checks are passive reads of what the collector recorded. `kernel_ownership` is the one
place a check declines to judge a whole class of host: a container reports its host's kernel,
so "is a newer kernel installed than the one running" is not a question about a container.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from scanners.host.reader import Snapshot

SSH_ROOT_LOGIN = "host-ssh-root-login"
KERNEL_REBOOT_PENDING = "host-kernel-reboot-pending"

# The allowlist entry's declared expectation for PermitRootLogin (the control): root may
# authenticate only with a key, or not at all.
SSH_EXPECTED = "prohibit-password"
SSH_RESTRICTED = frozenset({"no", "prohibit-password", "without-password", "forced-commands-only"})
SSH_PERMISSIVE = frozenset({"yes"})


@dataclass(frozen=True)
class Signal:
    method: str
    likelihood_ratio: float
    independence_class: str
    prior: float
    justification: str


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: str
    signals: tuple[Signal, ...]
    justification: str
    impact: str
    remediation: str
    references: tuple[str, ...] = ()
    passive: bool = True
    """0b.6: reading a snapshot sends nothing to the host, so every host check is passive."""
    mode: str = "light"
    not_applicable_reasons: frozenset[str] = frozenset()
    """ADR-032: none. The shared-kernel case is reported inconclusive, naming `not_applicable`
    in words, because ADR-032's reason list is closed and adding to it is a schema change."""

    @property
    def independence_classes(self) -> frozenset[str]:
        return frozenset(s.independence_class for s in self.signals)


CHECKS: dict[str, Check] = {
    c.check_id: c
    for c in [
        Check(
            SSH_ROOT_LOGIN,
            "sshd permits root login with a password",
            "high",
            (
                Signal(
                    "sshd_effective_config",
                    30.0,
                    "effective_config",
                    0.5,
                    "`sshd -T` prints the configuration sshd will actually apply, with includes "
                    "and defaults resolved, so a `yes` is read from the daemon's own account of "
                    "itself; it can still differ for a connection that matches a Match block, "
                    "which the output does not cover. One reading, one method: it cannot reach "
                    "`confirmed`.",
                ),
            ),
            "the effective sshd configuration is the authority on what sshd will accept",
            "A password guessed or leaked for the root account is a full takeover of the host, "
            "and sshd will accept it from anywhere the port is reachable.",
            "Set `PermitRootLogin prohibit-password` (or `no`) in sshd_config and reload sshd; "
            "log in as an unprivileged user and escalate.",
            ("https://man.openbsd.org/sshd_config#PermitRootLogin",),
        ),
        Check(
            KERNEL_REBOOT_PENDING,
            "A newer kernel is installed than the one running",
            "low",
            (
                Signal(
                    "running_kernel_release",
                    3.0,
                    "running_kernel",
                    0.5,
                    "`uname` reports the release the host is executing now; it is the control "
                    "for the comparison, and is wrong only if the box lies about its own kernel.",
                ),
                Signal(
                    "dpkg_installed_kernel_package",
                    3.0,
                    "package_database",
                    0.5,
                    "the package database lists which kernel images are installed; read on its "
                    "own it says nothing about what is running, which is why it is a separate "
                    "class from the running-kernel reading. Capped below `confirmed`: no "
                    "allowlisted command independently reports an installed kernel (spec 9).",
                ),
            ),
            "the comparison needs both readings, from two different interfaces of the host",
            "Fixes shipped in the newer kernel are not in effect until the host reboots. This "
            "check compares versions only: no advisory data is consulted, so it does not say "
            "the newer kernel fixes anything exploitable.",
            "Schedule a reboot into the installed kernel, then remove the old kernel packages.",
        ),
    ]
}


@dataclass(frozen=True)
class Observation:
    """One reading the verdict rests on, ready to become command_output evidence."""

    section: str
    reason_id: str
    label: str
    control_rationale: str
    output: str
    selection_method: str
    selection_detail: str


@dataclass(frozen=True)
class Verdict:
    check_id: str
    outcome: str  # reported | clear | inconclusive
    description: str = ""
    reason: str = ""
    observations: tuple[Observation, ...] = field(default_factory=tuple)


def _inconclusive(check: Check, snap: Snapshot, reason: str) -> Verdict:
    return Verdict(
        check.check_id,
        "inconclusive",
        description=(
            f"{check.title}: not assessed on {snap.hostname}. {reason}. "
            "This is not a pass: nothing was concluded about the host."
        ),
        reason=reason,
    )


def _unassessed(check: Check, snap: Snapshot) -> Verdict:
    runtime = snap.runtime or {}
    found = runtime.get("found") or "unknown"
    required = runtime.get("required") or "unknown"
    return _inconclusive(
        check,
        snap,
        f"host {snap.hostname} is unassessed: every section is {snap.unassessed} "
        f"(Python {found} found, {required} or newer required)",
    )


def _section(snap: Snapshot, name: str) -> tuple[dict[str, Any] | None, str]:
    """The collected body of `name`, or None and why not."""
    entry = snap.manifest.get(name)
    if entry is None:
        return None, f"section {name!r} is not in the snapshot's manifest"
    if entry.status == "collected":
        return snap.sections[name], ""
    detail = entry.reason if entry.status == "unavailable" else entry.error
    return None, f"section {name!r} is {entry.status}: {detail}"


def _observation_blocker(snap: Snapshot, observations: list[Observation]) -> str:
    """Why these observations cannot be cited as evidence, or '' if they can."""
    if snap.host_ref is None:
        return (
            "the host's machine_id_fingerprint was not collected, so evidence cannot name the host"
        )
    for obs in observations:
        index = snap.receipt_index(obs.reason_id)
        if index is None:
            return f"the receipt has no line for {obs.reason_id}, which this reading rests on"
        exit_status = snap.commands[index].get("exit_status")
        if isinstance(exit_status, bool) or not isinstance(exit_status, int):
            return f"the receipt line for {obs.reason_id} records no exit status"
    return ""


def _ssh_root_login(check: Check, snap: Snapshot) -> Verdict:
    body, why = _section(snap, "ssh")
    if body is None:
        return _inconclusive(check, snap, why)
    value = body["permitrootlogin"].strip().lower()
    if value in SSH_RESTRICTED:
        return Verdict(check.check_id, "clear")
    if value not in SSH_PERMISSIVE:
        return _inconclusive(
            check, snap, f"sections.ssh.permitrootlogin has an unrecognised value {value[:40]!r}"
        )
    obs = Observation(
        section="ssh",
        reason_id="ssh.effective",
        label="sections.ssh.permitrootlogin: the effective sshd configuration",
        control_rationale=(
            f"The control is the allowlist entry's declared expectation, PermitRootLogin "
            f"{SSH_EXPECTED} (or no): root may log in only with a key, or not at all. The test "
            f"is what `sshd -T` reported on this host: permitrootlogin {value}. Only this key "
            "was kept; the collector drops the rest of the output at parse time."
        ),
        output=f"permitrootlogin {value}",
        selection_method="lines_matching",
        selection_detail="permitrootlogin",
    )
    blocker = _observation_blocker(snap, [obs])
    if blocker:
        return _inconclusive(check, snap, blocker)
    return Verdict(
        check.check_id,
        "reported",
        description=(
            f"The effective sshd configuration on {snap.hostname} sets PermitRootLogin to "
            f"{value}, so sshd accepts a password for the root account. Expected: "
            f"{SSH_EXPECTED} or no. Read from section ssh of a snapshot collected at "
            f"{snap.collected_at_text}. This is what sshd -T reported for the default "
            "connection; a Match block can change it for specific users or addresses, and "
            "the output was not examined for those."
        ),
        observations=(obs,),
    )


_RELEASE = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\d+)-([A-Za-z0-9][A-Za-z0-9-]*)")
_IMAGE_PACKAGE = re.compile(
    r"linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+-[A-Za-z0-9][A-Za-z0-9-]*)"
)


def _release_key(release: str) -> tuple[tuple[int, int, int, int], str] | None:
    m = _RELEASE.fullmatch(release)
    if m is None:
        return None
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4])), m[5]


def _kernel_reboot_pending(check: Check, snap: Snapshot) -> Verdict:
    kernel, why = _section(snap, "kernel")
    if kernel is None:
        return _inconclusive(check, snap, why)
    ownership = kernel["kernel_ownership"]
    if ownership != "own":
        basis = ", ".join(kernel["ownership_basis"]) or "no marker could be read"
        return _inconclusive(
            check,
            snap,
            f"not_applicable: kernel_ownership={ownership} ({basis}), so the running kernel is "
            "not this host's own and a newer installed package says nothing about a reboot",
        )
    packages, why = _section(snap, "packages")
    if packages is None:
        return _inconclusive(check, snap, why)
    if packages["manager"] != "dpkg":
        return _inconclusive(
            check,
            snap,
            f"sections.packages.manager is {packages['manager'][:20]!r}; only dpkg kernel "
            "packages are compared in this slice",
        )
    if packages["truncated"]:
        return _inconclusive(
            check, snap, "sections.packages is truncated, so the newest kernel may be missing"
        )
    running = _release_key(kernel["running_release"])
    if running is None:
        return _inconclusive(
            check,
            snap,
            f"sections.kernel.running_release {kernel['running_release'][:40]!r} is not a "
            "release this check can order",
        )
    running_numbers, flavour = running
    installed: list[tuple[tuple[int, int, int, int], str, str]] = []
    for item in packages["items"]:
        m = _IMAGE_PACKAGE.fullmatch(item["name"])
        key = _release_key(m[1]) if m else None
        if key is not None and key[1] == flavour:
            installed.append((key[0], item["name"], item["version"]))
    if not installed:
        return _inconclusive(
            check,
            snap,
            f"no installed kernel of the running flavour {flavour!r} is in the package list",
        )
    installed.sort()
    newest_numbers, newest_name, newest_version = installed[-1]
    if newest_numbers <= running_numbers:
        return Verdict(check.check_id, "clear")

    running_obs = Observation(
        section="kernel",
        reason_id="kernel.uname",
        label="sections.kernel.running_version_string: the running kernel",
        control_rationale=(
            f"The control is the running kernel: {kernel['running_release']}, what the host is "
            "executing now."
        ),
        output=kernel["running_version_string"],
        selection_method="whole",
        selection_detail="the uname -srvm line as collected",
    )
    installed_obs = Observation(
        section="packages",
        reason_id="packages.debian",
        label="sections.packages.items: installed kernel images of the running flavour",
        control_rationale=(
            f"The test is the newest installed kernel image of the same flavour: {newest_name} "
            f"{newest_version}, newer than the running {kernel['running_release']}."
        ),
        output="\n".join(f"{name}\t{version}" for _, name, version in installed),
        selection_method="lines_matching",
        selection_detail=f"name is linux-image-<release>-{flavour}",
    )
    blocker = _observation_blocker(snap, [running_obs, installed_obs])
    if blocker:
        return _inconclusive(check, snap, blocker)
    skew = snap.clock.get("tz_offset_minutes")
    clock_note = (
        f"Both readings come from one snapshot, collected at {snap.collected_at_text} by the "
        f"host clock (clock source: {snap.clock.get('source', 'unstated')}"
        + (f", UTC offset {skew} minutes" if isinstance(skew, int) else "")
        + "). This check compares two versions and does no wall-clock arithmetic, so clock "
        "skew cannot change its result."
    )
    return Verdict(
        check.check_id,
        "reported",
        description=(
            f"{snap.hostname} is running kernel {kernel['running_release']}, but the package "
            f"database lists {newest_name} {newest_version} as installed, which is newer. The "
            f"newer kernel is not in use until the host reboots. {clock_note} Version numbers "
            "were compared; no advisory data was consulted."
        ),
        observations=(running_obs, installed_obs),
    )


_EVALUATORS = {SSH_ROOT_LOGIN: _ssh_root_login, KERNEL_REBOOT_PENDING: _kernel_reboot_pending}


def evaluate(check_id: str, snap: Snapshot) -> Verdict:
    check = CHECKS[check_id]
    if snap.unassessed:
        return _unassessed(check, snap)
    return _EVALUATORS[check_id](check, snap)
