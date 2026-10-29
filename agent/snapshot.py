"""The snapshot format (spec section 4) as construction helpers.

Python 3.6 syntax floor, stdlib only. A snapshot is a plain dict.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

from agent import version

STATUSES = ("collected", "unavailable", "error")

# Each count names what it counted (D64/D65). There is deliberately no "requests".
COUNT_FIELDS = (
    "commands_run",
    "commands_refused",
    "commands_failed",
    "files_read",
    "files_refused",
    "bytes_read",
    "sections_collected",
    "sections_unavailable",
    "sections_error",
)
_DERIVED = {
    "sections_collected": "collected",
    "sections_unavailable": "unavailable",
    "sections_error": "error",
}


def entry(
    section: str, status: str, reason: Optional[str] = None, error: Optional[str] = None
) -> Dict[str, Any]:
    """One manifest line. An unknown status cannot be constructed."""
    if status not in STATUSES:
        raise ValueError("unknown status: %r" % (status,))
    if status == "collected" and (reason or error):
        raise ValueError("a collected section carries no reason or error")
    if status == "unavailable" and not reason:
        raise ValueError("unavailable needs a machine reason")
    if status == "error" and not error:
        raise ValueError("error needs what failed")
    out = {"section": section, "status": status}  # type: Dict[str, Any]
    if reason:
        out["reason"] = reason
    if error:
        out["error"] = error
    return out


def make_counts(manifest: List[Dict[str, Any]], given: Dict[str, Any]) -> Dict[str, int]:
    """Named counts; the section tallies are derived from the manifest so they cannot disagree."""
    for key, value in given.items():
        if key not in COUNT_FIELDS:
            raise ValueError("unknown count: %r" % (key,))
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("count %r must be an int" % (key,))
    counts = {k: 0 for k in COUNT_FIELDS}
    counts.update(given)
    for key, status in _DERIVED.items():
        derived = len([m for m in manifest if m["status"] == status])
        if key in given and given[key] != derived:
            raise ValueError("%s disagrees with the manifest" % key)
        counts[key] = derived
    return counts


def _check(manifest: List[Dict[str, Any]], sections: Dict[str, Any]) -> None:
    names = [m["section"] for m in manifest]
    if len(set(names)) != len(names):
        raise ValueError("duplicate manifest section")
    for m in manifest:
        entry(m["section"], m["status"], m.get("reason"), m.get("error"))
        if m["status"] == "collected" and m["section"] not in sections:
            raise ValueError("collected section has no body: %s" % m["section"])
    for name in sections:
        if name not in names:
            raise ValueError("section not declared in manifest: %s" % name)
        status = [m for m in manifest if m["section"] == name][0]["status"]
        if status != "collected":
            raise ValueError("section body present but status is %s: %s" % (status, name))


def canonical(snap: Dict[str, Any]) -> bytes:
    """The bytes that are hashed: self_hash set to null, sorted keys, compact
    separators, ASCII-escaped JSON, UTF-8. ASCII escaping keeps the bytes identical
    across Python versions, so the 2.7 shim and this module agree."""
    body = dict(snap)
    body["self_hash"] = None
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return text.encode("utf-8")


def compute_hash(snap: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical(snap)).hexdigest()


def verify(snap: Dict[str, Any]) -> bool:
    """True if self_hash matches a recomputation.

    This detects truncation and accidental corruption in transit. It does
    not detect tampering: whoever changes the content can recompute the hash
    (corruption, not tampering). Signing is deferred (docs/23 item 7).
    """
    return snap.get("self_hash") == compute_hash(snap)


def build(
    manifest: List[Dict[str, Any]],
    sections: Dict[str, Any],
    counts: Dict[str, Any],
    host: Optional[Dict[str, Any]] = None,
    collected_at: str = "",
    clock: Optional[Dict[str, Any]] = None,
    receipt: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _check(manifest, sections)
    snap = {
        "snapshot_version": version.SNAPSHOT_VERSION,
        "schema": version.SCHEMA,
        "collector_version": version.COLLECTOR_VERSION,
        "collected_at": collected_at,
        "clock": clock or {},
        "host": host or {},
        "manifest": manifest,
        "sections": sections,
        "receipt": receipt or {},
        "self_hash": None,
        "counts": make_counts(manifest, counts),
    }  # type: Dict[str, Any]
    snap["self_hash"] = compute_hash(snap)
    return snap


def dumps(snap: Dict[str, Any]) -> str:
    """The file form: JSON, newline-terminated."""
    return json.dumps(snap, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
