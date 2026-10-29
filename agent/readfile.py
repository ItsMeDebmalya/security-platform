"""The allowlisted file reader (spec 5.2). 3.6 floor, stdlib only.

    reader = FileReader(receipt)
    results = reader.read_entry(allowlist.FILES[1])   # exact or dir+pattern entry
    result = reader.read("/etc/shadow")               # refused: excluded_by_allowlist

A file is read; a file is not stored. Only the keys the entry declares are kept, and the
receipt names keys, never values. Symlinks, FIFOs, foreign owners, exclusions and
off-list paths are refusals recorded in the receipt, not errors.
"""

import errno
import fnmatch
import os
import stat
from typing import Any, Dict, List, NamedTuple, Optional, Sequence

from agent import allowlist
from agent.receipt import Receipt


class FileResult(NamedTuple):
    path: str
    reason_id: str
    status: str  # read | absent | refused | error
    values: Dict[str, str]
    bytes_read: int
    truncated: bool
    refused_because: Optional[str] = None


def excluded(path: str, excludes: Sequence[Any] = allowlist.EXCLUDED) -> Optional[str]:
    for pattern, code, _why in excludes:
        if fnmatch.fnmatchcase(path, pattern):
            return str(code)
    return None


def parse_keys(text: str, keys: Sequence[str], fmt: str) -> Dict[str, str]:
    """Keep only declared keys (case-insensitive match, canonical name stored). First
    occurrence wins (sshd semantics); parsing stops at a `Match` block."""
    wanted = {k.lower(): k for k in keys}
    out = {}  # type: Dict[str, str]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "bare":  # a one-value file: the first line, stored under the one key
            out[keys[0]] = line
            break
        if fmt == "equals":
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
        else:
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1].strip() if len(parts) > 1 else ""
            if key.lower() == "match":
                break
        canon = wanted.get(key.strip().lower())
        if canon is not None and canon not in out:
            out[canon] = value
    return out


class FileReader:
    def __init__(
        self,
        receipt: Receipt,
        files: Sequence[allowlist.FileEntry] = allowlist.FILES,
        excludes: Sequence[Any] = allowlist.EXCLUDED,
    ) -> None:
        self.receipt = receipt
        self.files = tuple(files)
        self.excludes = tuple(excludes)

    def _matches(self, entry: allowlist.FileEntry, path: str) -> bool:
        if path == entry.path:
            return True
        d, pat = os.path.split(entry.path)
        pd, name = os.path.split(path)
        return d == pd and any(c in pat for c in "*?[") and fnmatch.fnmatchcase(name, pat)

    def read(self, path: str) -> FileResult:
        """Read a path only if some entry allows it and no exclusion matches it."""
        code = excluded(path, self.excludes)
        if code:
            return self._refuse(path, "", code)
        for entry in self.files:
            if self._matches(entry, path):
                return self._read_one(entry, path)
        return self._refuse(path, "", "not_in_allowlist")

    def read_entry(self, entry: allowlist.FileEntry) -> List[FileResult]:
        """Read every file an entry names (one for an exact path, many for a pattern)."""
        if entry not in self.files:
            return [self._refuse(entry.path, entry.reason_id, "not_in_allowlist")]
        d, pat = os.path.split(entry.path)
        if not any(c in pat for c in "*?["):
            paths = [entry.path]
        else:
            try:
                names = sorted(n for n in os.listdir(d) if fnmatch.fnmatchcase(n, pat))
            except OSError:
                names = []
            paths = [os.path.join(d, n) for n in names]
            if not paths:
                return [self._absent(entry, entry.path)]
        results = []
        for p in paths:
            code = excluded(p, self.excludes)
            results.append(
                self._refuse(p, entry.reason_id, code) if code else self._read_one(entry, p)
            )
        return results

    def _refuse(self, path: str, reason_id: str, why: str) -> FileResult:
        rec = {"path": path, "refused_because": why}  # type: Dict[str, Any]
        if reason_id:
            rec["reason_id"] = reason_id
        self.receipt.add_file_refusal(rec)
        return FileResult(path, reason_id, "refused", {}, 0, False, why)

    def _absent(self, entry: allowlist.FileEntry, path: str) -> FileResult:
        self.receipt.add_file(
            {
                "path": path,
                "reason_id": entry.reason_id,
                "present": False,
                "bytes_read": 0,
                "keys_extracted": [],
                "truncated": False,
            }
        )
        return FileResult(path, entry.reason_id, "absent", {}, 0, False)

    def _read_one(self, entry: allowlist.FileEntry, path: str) -> FileResult:
        if entry.needs_root and self.receipt.euid != 0:
            return self._refuse(path, entry.reason_id, "needs_root")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return self._absent(entry, path)
            if exc.errno == errno.ELOOP:
                return self._refuse(path, entry.reason_id, "symlink")
            if exc.errno in (errno.EACCES, errno.EPERM):
                return self._refuse(path, entry.reason_id, "permission_denied")
            return self._refuse(path, entry.reason_id, "open_failed")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return self._refuse(path, entry.reason_id, "not_regular_file")
            if st.st_uid not in (0, self.receipt.euid):
                return self._refuse(path, entry.reason_id, "bad_owner")
            data = b""
            while len(data) <= entry.max_bytes:
                chunk = os.read(fd, entry.max_bytes + 1 - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
        truncated = len(data) > entry.max_bytes
        data = data[: entry.max_bytes]
        values = parse_keys(data.decode("utf-8", "replace"), entry.keys, entry.fmt)
        self.receipt.add_file(
            {
                "path": path,
                "reason_id": entry.reason_id,
                "present": True,
                "bytes_read": len(data),
                "keys_extracted": sorted(values),
                "truncated": truncated,
                "mode": "%04o" % stat.S_IMODE(st.st_mode),
                "owner_uid": st.st_uid,
            }
        )
        return FileResult(path, entry.reason_id, "read", values, len(data), truncated)
