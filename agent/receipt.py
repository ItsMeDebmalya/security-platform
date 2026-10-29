"""The command receipt (spec 8), assembled as commands and files run. 3.6 floor, stdlib only."""

import datetime
import os
from typing import Any, Dict, List, Optional

RECEIPT_VERSION = 1


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user(uid: int) -> Optional[str]:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return None


class Receipt:
    """Append-only record. The runner and file reader write to it as they act."""

    def __init__(self, euid: Optional[int] = None, collector_version: str = "") -> None:
        self.euid = os.geteuid() if euid is None else euid
        self.collector_version = collector_version
        self.started_at = _now()
        self.commands: List[Dict[str, Any]] = []
        self.commands_refused: List[Dict[str, Any]] = []
        self.files: List[Dict[str, Any]] = []
        self.files_refused: List[Dict[str, Any]] = []

    def add_command(self, record: Dict[str, Any]) -> None:
        self.commands.append(record)

    def add_command_refusal(self, record: Dict[str, Any]) -> None:
        self.commands_refused.append(record)

    def add_file(self, record: Dict[str, Any]) -> None:
        self.files.append(record)

    def add_file_refusal(self, record: Dict[str, Any]) -> None:
        self.files_refused.append(record)

    def counts(self) -> Dict[str, int]:
        """Named counts using agent.snapshot.COUNT_FIELDS names."""
        return {
            "commands_run": len(self.commands),
            "commands_refused": len(self.commands_refused),
            "commands_failed": len([c for c in self.commands if c.get("failed")]),
            "files_read": len([f for f in self.files if f.get("present")]),
            "files_refused": len(self.files_refused),
            "bytes_read": sum(f.get("bytes_read", 0) for f in self.files),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_version": RECEIPT_VERSION,
            "collector_version": self.collector_version,
            "effective_uid": self.euid,
            "effective_user": _user(self.euid),
            "started_at": self.started_at,
            "finished_at": _now(),
            "commands": list(self.commands),
            "commands_refused": list(self.commands_refused),
            "files": list(self.files),
            "files_refused": list(self.files_refused),
        }
