"""The argv-only command runner (spec 5.1). 3.6 floor, stdlib only.

    runner = Runner(receipt)
    result = runner.run(allowlist.COMMANDS[0])      # an allowlist entry
    result = runner.request(["uname", "-a"])        # an argv: runs only on an exact match

Every outcome is a CommandResult and a receipt record: ran, refused, missing binary,
timeout. Nothing raises for a bad command; a refusal is data.
"""

import contextlib
import os
import select
import signal
import subprocess
import time
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

from agent import allowlist
from agent.receipt import Receipt

ENV_FIXED = (("LC_ALL", "C"), ("TZ", "UTC"))


class CommandResult(NamedTuple):
    reason_id: str
    status: str  # ran | refused | missing_binary | timeout | error
    exit_status: Optional[int]
    stdout: str  # at most max_bytes, decoded with replacement
    stdout_bytes: int  # total produced, including what was dropped
    stdout_truncated: bool
    stderr_bytes: int
    duration_ms: int
    refused_because: Optional[str] = None
    failed: bool = False


def environment(bin_dirs: Sequence[str]) -> Dict[str, str]:
    """A scrubbed fixed env; nothing is inherited."""
    env = dict(ENV_FIXED)
    env["PATH"] = ":".join(bin_dirs)
    return env


def resolve_binary(name: str, bin_dirs: Sequence[str]) -> Tuple[Optional[str], Optional[str]]:
    """(path, None) | (None, 'binary_not_found') | (None, 'binary_unsafe').

    Looked up only in bin_dirs. A symlink is acceptable only if it lands, as a regular
    executable file, inside one of those directories (usr-merge /bin -> usr/bin).
    """
    if not name or "/" in name or name in (".", ".."):
        return None, "binary_unsafe"
    real_dirs = set(os.path.realpath(d) for d in bin_dirs)
    unsafe = False
    for d in bin_dirs:
        cand = os.path.join(d, name)
        if not os.path.lexists(cand):
            continue
        real = os.path.realpath(cand)
        if os.path.dirname(real) in real_dirs and os.path.isfile(real) and os.access(real, os.X_OK):
            return real, None
        unsafe = True
    return (None, "binary_unsafe") if unsafe else (None, "binary_not_found")


class Runner:
    def __init__(
        self,
        receipt: Receipt,
        commands: Sequence[allowlist.CommandEntry] = allowlist.COMMANDS,
        bin_dirs: Sequence[str] = allowlist.BIN_DIRS,
    ) -> None:
        self.receipt = receipt
        self.commands = tuple(commands)
        self.bin_dirs = tuple(bin_dirs)

    def request(self, argv: Sequence[str]) -> CommandResult:
        """Run an argv only if it exactly matches an allowlist entry."""
        for entry in self.commands:
            if tuple(argv) == entry.argv:
                return self.run(entry)
        self.receipt.add_command_refusal(
            {"argv_requested": list(argv), "refused_because": "not_in_allowlist"}
        )
        return CommandResult("", "refused", None, "", 0, False, 0, 0, "not_in_allowlist", True)

    def _refuse(self, entry: allowlist.CommandEntry, why: str) -> CommandResult:
        self.receipt.add_command_refusal(
            {
                "argv_requested": list(entry.argv),
                "reason_id": entry.reason_id,
                "refused_because": why,
            }
        )
        return CommandResult(entry.reason_id, "refused", None, "", 0, False, 0, 0, why, True)

    def run(self, entry: allowlist.CommandEntry) -> CommandResult:
        if entry not in self.commands:
            return self._refuse(entry, "not_in_allowlist")
        if entry.needs_root and self.receipt.euid != 0:
            return self._refuse(entry, "needs_root")
        path, problem = resolve_binary(entry.argv[0], self.bin_dirs)
        if path is None:
            return self._finish(entry, ["?"], "missing_binary", None, b"", 0, 0, 0, problem)
        argv = [path, *entry.argv[1:]]
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                shell=False,
                env=environment(self.bin_dirs),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            return self._finish(entry, argv, "error", None, b"", 0, 0, 0, type(exc).__name__)
        kept, total, err_total, timed_out = self._drain(proc, entry)
        ms = int((time.monotonic() - start) * 1000)
        code = proc.returncode
        status = "timeout" if timed_out else "ran"
        return self._finish(entry, argv, status, code, kept, total, err_total, ms, None)

    @staticmethod
    def _drain(proc: Any, entry: allowlist.CommandEntry) -> Tuple[bytes, int, int, bool]:
        """Read both pipes to EOF within the timeout; keep at most max_bytes of stdout.
        Excess is counted and dropped (so the child never blocks), and a timeout kills
        the whole process group."""
        deadline = time.monotonic() + entry.timeout_s
        out = proc.stdout.fileno()
        err = proc.stderr.fileno()
        open_fds = {out, err}
        kept = []  # type: List[bytes]
        counts = {out: 0, err: 0}
        timed_out = False
        while open_fds:
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            ready, _, _ = select.select(list(open_fds), [], [], left)
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.discard(fd)
                    continue
                if fd == out:
                    room = entry.max_bytes - counts[out]
                    if room > 0:
                        kept.append(chunk[:room])
                counts[fd] += len(chunk)
        if timed_out:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
        return b"".join(kept), counts[out], counts[err], timed_out

    def _finish(
        self,
        entry: allowlist.CommandEntry,
        argv: List[str],
        status: str,
        code: Optional[int],
        kept: bytes,
        total: int,
        err_total: int,
        ms: int,
        problem: Optional[str],
    ) -> CommandResult:
        truncated = total > entry.max_bytes
        failed = status != "ran" or (code != 0 and not entry.nonzero_ok)
        record = {
            "argv": argv,
            "reason_id": entry.reason_id,
            "status": status,
            "exit_status": code,
            "duration_ms": ms,
            "stdout_bytes": total,
            "stdout_truncated": truncated,
            "stderr_bytes": err_total,
            "read_for": list(entry.read_for),
            "failed": failed,
        }  # type: Dict[str, Any]
        if problem:
            record["problem"] = problem
        self.receipt.add_command(record)
        return CommandResult(
            entry.reason_id,
            status,
            code,
            kept.decode("utf-8", "replace"),
            total,
            truncated,
            err_total,
            ms,
            problem,
            failed,
        )
