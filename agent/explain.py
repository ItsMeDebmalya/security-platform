"""Plain-text renderings for the server's owner (spec 8, 8.1). 3.6 floor, stdlib only.

render_receipt  --explain       what the agent DID, from a snapshot's receipt
render_plan     --explain-plan  what the agent WILL do, from the enforced allowlists

Both are pure string builders over data. The plan reads the same allowlist objects the
runner and the file reader enforce, so it cannot drift from them, and it opens and runs
nothing. Neither prints a collected value: names, paths, argv and reasons only.
"""

import json
import re
from typing import Any, Dict, List, Optional, Sequence

from agent import allowlist

_BARE = re.compile(r"^[A-Za-z0-9_./=:+@%-]+$")


def _arg(arg: str) -> str:
    """Shown bare when plain, else as an escaped JSON string (so \\t and \\n are visible)."""
    if _BARE.match(arg):
        return arg
    return json.dumps(arg)


def _argv(argv: Sequence[str]) -> str:
    return " ".join(_arg(a) for a in argv)


def _reasons() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in allowlist.COMMANDS:
        out[c.reason_id] = c.reason
    for f in allowlist.FILES:
        out[f.reason_id] = f.reason
    return out


def render_receipt(receipt: Dict[str, Any]) -> str:
    why = _reasons()
    lines: List[str] = []
    lines.append("What the collector did on this host")
    lines.append("===================================")
    lines.append(
        "Ran as %s (uid %s), from %s to %s, collector %s."
        % (
            receipt.get("effective_user") or "an unnamed user",
            receipt.get("effective_uid"),
            receipt.get("started_at"),
            receipt.get("finished_at"),
            receipt.get("collector_version"),
        )
    )
    cmds = receipt.get("commands") or []
    lines += ["", "Commands it ran (%d)" % len(cmds), "--------------------"]
    for c in cmds:
        lines.append("* %s" % _argv(c.get("argv") or []))
        lines.append("    id: %s" % c.get("reason_id"))
        if why.get(c.get("reason_id", "")):
            lines.append("    why: %s" % why[c["reason_id"]])
        lines.append(
            "    result: %s, exit %s, %s bytes of output%s"
            % (
                c.get("status"),
                c.get("exit_status"),
                c.get("stdout_bytes"),
                " (cut at the cap)" if c.get("stdout_truncated") else "",
            )
        )
        lines.append("    used for: %s" % ", ".join(c.get("read_for") or []))
    if not cmds:
        lines.append("(none)")
    refused = receipt.get("commands_refused") or []
    lines += [
        "",
        "Commands it refused to run (%d)" % len(refused),
        "-------------------------------",
    ]
    for c in refused:
        lines.append("* %s" % _argv(c.get("argv_requested") or []))
        if c.get("reason_id"):
            lines.append("    id: %s" % c["reason_id"])
        lines.append("    refused because: %s" % c.get("refused_because"))
    if not refused:
        lines.append("(none)")
    files = receipt.get("files") or []
    lines += ["", "Files it looked at (%d)" % len(files), "-----------------------"]
    for f in files:
        lines.append("* %s" % f.get("path"))
        lines.append("    id: %s" % f.get("reason_id"))
        if why.get(f.get("reason_id", "")):
            lines.append("    why: %s" % why[f["reason_id"]])
        if f.get("present"):
            lines.append(
                "    read %s bytes; kept only the keys: %s"
                % (f.get("bytes_read"), ", ".join(f.get("keys_extracted") or []) or "(none)")
            )
        else:
            lines.append("    not present on this host")
    if not files:
        lines.append("(none)")
    frefused = receipt.get("files_refused") or []
    lines += ["", "Files it refused to read (%d)" % len(frefused), "-----------------------------"]
    for f in frefused:
        lines.append("* %s" % f.get("path"))
        lines.append("    refused because: %s" % f.get("refused_because"))
    if not frefused:
        lines.append("(none)")
    lines += [
        "",
        "Nothing here shows the contents of any file. Values that looked like secrets were",
        "replaced before the snapshot was written.",
    ]
    return "\n".join(lines) + "\n"


def render_plan(
    commands: Optional[Sequence[allowlist.CommandEntry]] = None,
    files: Optional[Sequence[allowlist.FileEntry]] = None,
    excluded: Optional[Sequence[Any]] = None,
) -> str:
    commands = allowlist.COMMANDS if commands is None else commands
    files = allowlist.FILES if files is None else files
    excluded = allowlist.EXCLUDED if excluded is None else excluded
    lines: List[str] = []
    lines.append("What the collector will do (nothing was run to produce this page)")
    lines.append("=================================================================")
    lines.append("It runs only the commands and reads only the files listed here; anything else")
    lines.append(
        "is refused and recorded. Binaries are looked up only in: %s."
        % ", ".join(allowlist.BIN_DIRS)
    )
    lines += ["", "Commands (%d)" % len(commands), "-------------"]
    for c in commands:
        lines.append("* %s" % _argv(c.argv))
        lines.append("    id: %s" % c.reason_id)
        lines.append("    why: %s" % c.reason)
        lines.append("    feeds: %s" % ", ".join(c.read_for))
        lines.append("    timeout: %g s; output cap: %d bytes" % (c.timeout_s, c.max_bytes))
        lines.append("    needs root: %s" % ("yes" if c.needs_root else "no"))
    lines += ["", "Files (%d)" % len(files), "----------"]
    for f in files:
        lines.append("* %s" % f.path)
        lines.append("    id: %s" % f.reason_id)
        lines.append("    why: %s" % f.reason)
        lines.append("    judged from it: %s" % f.judged_from)
        lines.append("    the only keys kept: %s" % ", ".join(f.keys))
        lines.append("    read cap: %d bytes" % f.max_bytes)
    lines += [
        "",
        "Never read, whatever asks (%d rules)" % len(excluded),
        "------------------------------------",
    ]
    for pattern, code, why in excluded:
        lines.append("* %s    [%s]  %s" % (pattern, code, why))
    lines += ["", "No command was run and no file was opened to print this."]
    return "\n".join(lines) + "\n"
