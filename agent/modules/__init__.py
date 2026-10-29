"""Collection modules (spec 4, 6). Each returns facts and a status, and judges nothing.

A module is `collect(runner, reader) -> Outcome`. Every command and path a module uses
is an allowlist constant looked up by its reason id; no collected value is ever passed
on as a path or an argument (spec 5.1).
"""

from typing import Any, Dict, NamedTuple, Optional

from agent.readfile import FileReader, FileResult
from agent.run import CommandResult, Runner


class Outcome(NamedTuple):
    status: str  # collected | unavailable | error
    body: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None  # unavailable: a machine reason
    error: Optional[str] = None  # error: what failed


def collected(body: Dict[str, Any]) -> Outcome:
    return Outcome("collected", body)


def unavailable(reason: str) -> Outcome:
    return Outcome("unavailable", None, reason=reason)


def failed(error: str) -> Outcome:
    return Outcome("error", None, error=error)


def command(runner: Runner, reason_id: str) -> Any:
    for entry in runner.commands:
        if entry.reason_id == reason_id:
            return entry
    raise KeyError(reason_id)


def file_entry(reader: FileReader, reason_id: str) -> Any:
    for entry in reader.files:
        if entry.reason_id == reason_id:
            return entry
    raise KeyError(reason_id)


def command_problem(res: CommandResult) -> Optional[Outcome]:
    """The section outcome for a command that did not yield output, else None.

    A refusal for lack of root is `unavailable`; a missing binary is `unavailable`;
    anything else that went wrong is an `error` naming it. Never a silent pass."""
    if res.status == "refused":
        if res.refused_because == "needs_root":
            return unavailable("needs_root")
        return failed("command_refused:%s:%s" % (res.reason_id, res.refused_because))
    if res.status == "missing_binary":
        if res.refused_because == "binary_not_found":
            return unavailable("binary_not_found")
        return failed("command_binary:%s:%s" % (res.reason_id, res.refused_because))
    if res.status in ("timeout", "error"):
        return failed("command_%s:%s" % (res.status, res.reason_id))
    if res.failed:
        return failed("command_failed:%s:%s" % (res.reason_id, res.exit_status))
    return None


def file_problem(res: FileResult) -> Optional[Outcome]:
    """The section outcome for a file that yielded nothing, else None."""
    if res.status == "absent":
        return unavailable("file_absent")
    if res.status == "refused":
        return unavailable(str(res.refused_because))
    if res.status != "read":
        return failed("file_%s:%s" % (res.status, res.reason_id))
    return None
