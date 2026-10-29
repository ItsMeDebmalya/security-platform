"""The snapshot reader: the one place a host snapshot becomes data (spec 4, 9, 13).

A snapshot comes from a machine that may be compromised, so it is read as HOSTILE INPUT:

1. Limits are checked on the raw bytes, BEFORE `json.loads`, because the parser is the thing
   being defended (13.1). Exceeding any one is a scan error, never a truncation: truncating
   hostile input keeps it and makes the artefact disagree with what we claim about it.
2. Every field is validated for type, shape and enum membership before anything uses it, and a
   wrong type is a scan error NAMING the field - not a coercion, not a None flowing inward
   (13.4). A known `snapshot_version` says which schema we expect, never that the file matches.
3. No value from here becomes a path, a filename, an argument, a URL, an identifier or a format
   string (13.2). `load_file` is the only function that touches the filesystem and it opens the
   operator's own command-line argument, never anything read from a snapshot.

A broken snapshot - unknown version, a section the manifest promised but did not deliver, a
malformed file, a self-hash mismatch - is a SCAN ERROR, never an inconclusive and never a clear
(R1/R2, D66's rule). A snapshot in which every section is `unsupported_runtime` is read
successfully and reported as UNASSESSED: the host is named and is never clear.

What this does not do: it does not make a snapshot trustworthy. A validated snapshot is
well-formed, not true; what the platform claims is "this is what the host reported" (13.5).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanners.host.render import visible

# --- the pre-parse limits (spec 13.1): named, with their reasons -------------------------

MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 16
MAX_STRING = 64 * 1024
MAX_ARRAY = 50_000
MAX_KEYS = 200_000

LIMIT_REASONS: dict[str, str] = {
    "MAX_BYTES": (
        "A multi-gigabyte snapshot is a denial of the scan pipeline, not a scan. 16 MiB is about "
        "50x a real fleet snapshot (tens of KB to a few MB with a long package list)."
    ),
    "MAX_DEPTH": (
        "Deep nesting is a stack-exhaustion primitive against any recursive reader, and Python's "
        "own parser recurses. A real snapshot nests about 6 deep; 16 leaves room to grow."
    ),
    "MAX_STRING": (
        "One field holding megabytes reaches a report renderer, a PDF engine and a log line. "
        "64 KiB is far above any real value (the longest are an os-release text or a uname line)."
    ),
    "MAX_ARRAY": (
        "A million-element manifest is the same attack as a deep one wearing a different hat. "
        "A server has a few thousand packages; 50,000 is ~20x that."
    ),
    "MAX_KEYS": (
        "Breadth, where the others defend depth: a package list is two keys per package, so "
        "200,000 keys is ~25x a real package list."
    ),
}

SUPPORTED_SNAPSHOT_VERSION = 1
SCHEMA = "security-platform/host-snapshot"
STATUSES = ("collected", "unavailable", "error")
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
KERNEL_OWNERSHIP = ("own", "shared", "unknown")
UNSUPPORTED_RUNTIME = "unsupported_runtime"

_TOP_LEVEL = frozenset(
    {
        "snapshot_version",
        "schema",
        "collector_version",
        "collected_at",
        "clock",
        "host",
        "manifest",
        "sections",
        "runtime",
        "receipt",
        "self_hash",
        "counts",
    }
)
_REQUIRED_TOP_LEVEL = _TOP_LEVEL - {"runtime"}
_HOST_REF = re.compile(r"^sha256:[0-9a-f]{16}$")
_SELF_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SECTION_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"

# One alternation, so a string that never closes falls to the lone-quote branch and is refused
# at once. That keeps the scan linear however hostile the input.
_TOKEN = re.compile(rb'"(?:[^"\\]|\\.)*+"|[\[\]{},:]|[^"\[\]{},:]+|"', re.DOTALL)


class SnapshotError(ValueError):
    """A scan error: the snapshot cannot be read. Names the field; never quotes raw bytes."""

    def __init__(self, field_name: str, message: str) -> None:
        self.field = field_name
        self.reason = message
        super().__init__(f"snapshot {field_name}: {message}")


def _shown(value: object, limit: int = 60) -> str:
    """A value as it may appear in an error: escaped, bounded, and clearly data."""
    text = visible(repr(value) if not isinstance(value, str) else value, keep=frozenset())
    text = text.replace("<", "\\x3c").replace(">", "\\x3e")
    return repr(text[:limit] + ("..." if len(text) > limit else ""))


def _limit(name: str, where: str, detail: str) -> SnapshotError:
    return SnapshotError(where, f"{name} exceeded ({detail}); refused, never truncated")


# --- stage 1: limits on the raw bytes, before json.loads -----------------------------------


def _check_raw(data: bytes) -> None:
    if len(data) > MAX_BYTES:
        raise _limit("MAX_BYTES", "file", f"{len(data)} bytes > {MAX_BYTES}")
    stack: list[list[Any]] = []  # [bracket, commas]
    keys = 0
    for m in _TOKEN.finditer(data):
        tok = m.group(0)
        head = tok[:1]
        if head == b'"':
            if len(tok) < 2 or not tok.endswith(b'"'):
                raise SnapshotError("file", "malformed JSON (a string never closes)")
            inner = len(tok) - 2
            if (
                b"\\" not in tok and tok.isascii() and inner > MAX_STRING
            ) or inner > 12 * MAX_STRING:
                raise _limit("MAX_STRING", "file", f"a string of {inner} bytes")
        elif head in (b"[", b"{"):
            stack.append([head, 0])
            if len(stack) > MAX_DEPTH:
                raise _limit("MAX_DEPTH", "file", f"nesting deeper than {MAX_DEPTH}")
        elif head in (b"]", b"}"):
            if not stack:
                raise SnapshotError("file", "malformed JSON (unbalanced brackets)")
            stack.pop()
        elif head == b",":
            if stack:
                stack[-1][1] += 1
                if stack[-1][0] == b"[" and stack[-1][1] + 1 > MAX_ARRAY:
                    raise _limit("MAX_ARRAY", "file", f"an array longer than {MAX_ARRAY}")
        elif head == b":":
            keys += 1
            if keys > MAX_KEYS:
                raise _limit("MAX_KEYS", "file", f"more than {MAX_KEYS} keys")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SnapshotError("file", f"duplicate key {_shown(key)}: an ambiguous object")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise SnapshotError("file", f"the constant {_shown(name)} is not valid in a snapshot")


def _walk_limits(node: Any, path: str) -> None:
    """The exact string and array limits, over the parsed tree (the raw pass is a fast bound)."""
    if isinstance(node, str):
        if len(node) > MAX_STRING:
            raise _limit("MAX_STRING", path or "file", f"{len(node)} characters > {MAX_STRING}")
    elif isinstance(node, list):
        if len(node) > MAX_ARRAY:
            raise _limit("MAX_ARRAY", path or "file", f"{len(node)} elements > {MAX_ARRAY}")
        for i, item in enumerate(node):
            _walk_limits(item, f"{path}.{i}" if path else str(i))
    elif isinstance(node, dict):
        for key, item in node.items():
            if len(key) > MAX_STRING:
                raise _limit("MAX_STRING", path or "file", "a key is too long")
            _walk_limits(item, f"{path}.{key}" if path else key)


# --- stage 2: shape and types --------------------------------------------------------------


def _obj(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotError(path, f"expected an object, got {type(value).__name__}")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise SnapshotError(path, f"expected an array, got {type(value).__name__}")
    return value


def _str(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SnapshotError(path, f"expected a string, got {type(value).__name__}")
    if not value and not allow_empty:
        raise SnapshotError(path, "expected a non-empty string")
    return value


def _int(value: Any, path: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnapshotError(path, f"expected an integer, got {type(value).__name__}")
    if minimum is not None and value < minimum:
        raise SnapshotError(path, f"expected an integer >= {minimum}, got {value}")
    return value


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise SnapshotError(path, f"expected true or false, got {type(value).__name__}")
    return value


def _get(obj: dict[str, Any], key: str, path: str) -> Any:
    if key not in obj:
        raise SnapshotError(f"{path}.{key}" if path else key, "required field is missing")
    return obj[key]


def _timestamp(value: Any, path: str) -> datetime:
    text = _str(value, path)
    try:
        return datetime.strptime(text, _TIMESTAMP).replace(tzinfo=UTC)
    except ValueError:
        raise SnapshotError(
            path, f"expected a UTC timestamp like 2026-10-29T09:50:04Z, got {_shown(text)}"
        ) from None


@dataclass(frozen=True)
class ManifestEntry:
    status: str
    reason: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Snapshot:
    """A validated snapshot. Well-formed, not trustworthy (spec 13.5)."""

    hostname: str
    host_ref: str | None
    collected_at: datetime
    collected_at_text: str
    clock: dict[str, Any]
    manifest: dict[str, ManifestEntry]
    sections: dict[str, dict[str, Any]]
    commands: list[dict[str, Any]]
    runtime: dict[str, Any] | None
    unassessed: str | None = None
    self_hash: str = ""
    collector_version: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    def receipt_index(self, reason_id: str) -> int | None:
        for i, command in enumerate(self.commands):
            if command["reason_id"] == reason_id:
                return i
        return None


def _validate_host(host: Any) -> tuple[str, str | None]:
    host = _obj(host, "host")
    name = _str(_get(host, "hostname", "host"), "host.hostname")
    if not _HOSTNAME.fullmatch(name) or name.strip(".") == "":
        raise SnapshotError(
            "host.hostname",
            f"not a hostname (letters, digits, '.', '-', '_'; at most 253): {_shown(name)}",
        )
    ref = host.get("machine_id_fingerprint")
    if ref is not None:
        ref = _str(ref, "host.machine_id_fingerprint")
        if not _HOST_REF.fullmatch(ref):
            raise SnapshotError("host.machine_id_fingerprint", f"not a fingerprint: {_shown(ref)}")
    if "os_release_text" in host and host["os_release_text"] is not None:
        _str(host["os_release_text"], "host.os_release_text", allow_empty=True)
    if "os" in host:
        _obj(host["os"], "host.os")
    return name, ref


def _validate_clock(raw: Any) -> dict[str, Any]:
    clock = _obj(raw, "clock")
    if "source" in clock:
        _str(clock["source"], "clock.source")
    for key in ("tz_offset_minutes", "monotonic_ms"):
        if key in clock:
            _int(clock[key], f"clock.{key}")
    return clock


def _validate_manifest(manifest: Any) -> dict[str, ManifestEntry]:
    entries = _list(manifest, "manifest")
    out: dict[str, ManifestEntry] = {}
    for i, raw in enumerate(entries):
        path = f"manifest.{i}"
        item = _obj(raw, path)
        extra = set(item) - {"section", "status", "reason", "error"}
        if extra:
            raise SnapshotError(path, f"unknown field {_shown(sorted(extra)[0])}")
        section = _str(_get(item, "section", path), f"{path}.section")
        if not _SECTION_NAME.fullmatch(section):
            raise SnapshotError(f"{path}.section", f"not a section name: {_shown(section)}")
        status = _str(_get(item, "status", path), f"{path}.status")
        if status not in STATUSES:
            raise SnapshotError(
                f"{path}.status", f"not one of {', '.join(STATUSES)}: {_shown(status)}"
            )
        reason = item.get("reason")
        error = item.get("error")
        if reason is not None:
            _str(reason, f"{path}.reason")
        if error is not None:
            _str(error, f"{path}.error")
        if status == "collected" and (reason or error):
            raise SnapshotError(path, "a collected section carries no reason or error")
        if status == "unavailable" and not reason:
            raise SnapshotError(f"{path}.reason", "an unavailable section needs a machine reason")
        if status == "error" and not error:
            raise SnapshotError(f"{path}.error", "an error section needs what failed")
        if section in out:
            raise SnapshotError(f"{path}.section", f"duplicate section {_shown(section)}")
        out[section] = ManifestEntry(status, reason, error)
    return out


def _validate_kernel(body: dict[str, Any]) -> None:
    p = "sections.kernel"
    _str(_get(body, "running_release", p), f"{p}.running_release")
    _str(_get(body, "running_version_string", p), f"{p}.running_version_string")
    _str(_get(body, "architecture", p), f"{p}.architecture")
    own = _str(_get(body, "kernel_ownership", p), f"{p}.kernel_ownership")
    if own not in KERNEL_OWNERSHIP:
        raise SnapshotError(
            f"{p}.kernel_ownership", f"not one of {', '.join(KERNEL_OWNERSHIP)}: {_shown(own)}"
        )
    for i, basis in enumerate(_list(_get(body, "ownership_basis", p), f"{p}.ownership_basis")):
        _str(basis, f"{p}.ownership_basis.{i}")


def _validate_ssh(body: dict[str, Any]) -> None:
    p = "sections.ssh"
    _str(_get(body, "permitrootlogin", p), f"{p}.permitrootlogin")
    for key, value in body.items():
        _str(value, f"{p}.{key}", allow_empty=True)


def _validate_packages(body: dict[str, Any]) -> None:
    p = "sections.packages"
    _str(_get(body, "manager", p), f"{p}.manager")
    _bool(_get(body, "truncated", p), f"{p}.truncated")
    for i, raw in enumerate(_list(_get(body, "items", p), f"{p}.items")):
        item = _obj(raw, f"{p}.items.{i}")
        _str(_get(item, "name", f"{p}.items.{i}"), f"{p}.items.{i}.name")
        _str(_get(item, "version", f"{p}.items.{i}"), f"{p}.items.{i}.version")


def _validate_host_identity(body: dict[str, Any]) -> None:
    p = "sections.host_identity"
    _str(_get(body, "hostname", p), f"{p}.hostname")
    ref = body.get("machine_id_fingerprint")
    if ref is not None and not _HOST_REF.fullmatch(_str(ref, f"{p}.machine_id_fingerprint")):
        raise SnapshotError(f"{p}.machine_id_fingerprint", f"not a fingerprint: {_shown(ref)}")


_SECTION_VALIDATORS = {
    "kernel": _validate_kernel,
    "ssh": _validate_ssh,
    "packages": _validate_packages,
    "host_identity": _validate_host_identity,
}


def _validate_sections(raw: Any, manifest: dict[str, ManifestEntry]) -> dict[str, dict[str, Any]]:
    sections = _obj(raw, "sections")
    for name in sections:
        if name not in manifest:
            raise SnapshotError(
                f"sections.{name}", "a body for a section the manifest does not declare"
            )
        if manifest[name].status != "collected":
            raise SnapshotError(
                f"sections.{name}",
                f"a body is present but the manifest says {manifest[name].status}",
            )
    out: dict[str, dict[str, Any]] = {}
    for name, entry in manifest.items():
        if entry.status != "collected":
            continue
        if name not in sections:
            raise SnapshotError(
                f"sections.{name}", "the manifest promised this section but it was not delivered"
            )
        body = _obj(sections[name], f"sections.{name}")
        validator = _SECTION_VALIDATORS.get(name)
        if validator:
            validator(body)
        out[name] = body
    return out


def _validate_counts(raw: Any, manifest: dict[str, ManifestEntry]) -> None:
    counts = _obj(raw, "counts")
    for key in counts:
        if key not in COUNT_FIELDS:
            raise SnapshotError(f"counts.{key}", "unknown count")
    for key in COUNT_FIELDS:
        _int(_get(counts, key, "counts"), f"counts.{key}", minimum=0)
    for key, status in (
        ("sections_collected", "collected"),
        ("sections_unavailable", "unavailable"),
        ("sections_error", "error"),
    ):
        tally = sum(1 for e in manifest.values() if e.status == status)
        if counts[key] != tally:
            raise SnapshotError(f"counts.{key}", f"says {counts[key]} but the manifest has {tally}")


def _validate_receipt(raw: Any) -> list[dict[str, Any]]:
    receipt = _obj(raw, "receipt")
    commands = _list(receipt.get("commands", []), "receipt.commands")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(commands):
        p = f"receipt.commands.{i}"
        command = _obj(item, p)
        _str(_get(command, "reason_id", p), f"{p}.reason_id")
        argv = _list(_get(command, "argv", p), f"{p}.argv")
        if not argv:
            raise SnapshotError(f"{p}.argv", "expected a non-empty array")
        for j, arg in enumerate(argv):
            _str(arg, f"{p}.argv.{j}", allow_empty=True)
        if command.get("exit_status") is not None:
            _int(command["exit_status"], f"{p}.exit_status")
        if "stdout_bytes" in command:
            _int(command["stdout_bytes"], f"{p}.stdout_bytes", minimum=0)
        if "stdout_truncated" in command:
            _bool(command["stdout_truncated"], f"{p}.stdout_truncated")
        if "status" in command:
            _str(command["status"], f"{p}.status")
        out.append(command)
    for key in ("commands_refused", "files", "files_refused"):
        if key in receipt:
            for j, item in enumerate(_list(receipt[key], f"receipt.{key}")):
                _obj(item, f"receipt.{key}.{j}")
    return out


def _validate_runtime(raw: Any) -> dict[str, Any]:
    runtime = _obj(raw, "runtime")
    for key in ("found", "executable", "required"):
        if key in runtime and runtime[key] is not None:
            _str(runtime[key], f"runtime.{key}", allow_empty=True)
    if "searched" in runtime:
        for i, item in enumerate(_list(runtime["searched"], "runtime.searched")):
            _str(item, f"runtime.searched.{i}", allow_empty=True)
    return runtime


def _canonical_hash(data: dict[str, Any]) -> str:
    """The collector's own recipe (agent/snapshot.py): self_hash null, sorted, compact, ASCII."""
    body = dict(data)
    body["self_hash"] = None
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse(data: bytes) -> Snapshot:
    """Bytes to a validated `Snapshot`, or a `SnapshotError`."""
    _check_raw(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SnapshotError("file", "not valid UTF-8") from None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_refuse_constant,
        )
    except SnapshotError:
        raise
    except RecursionError:
        raise _limit("MAX_DEPTH", "file", "the parser's own recursion limit") from None
    except ValueError:
        raise SnapshotError("file", "malformed JSON") from None
    _walk_limits(parsed, "")
    top = _obj(parsed, "file")

    # The version first: it says which schema to expect, and nothing else is read until it is known.
    version = _get(top, "snapshot_version", "")
    if isinstance(version, bool) or version != SUPPORTED_SNAPSHOT_VERSION:
        raise SnapshotError(
            "snapshot_version",
            f"unknown version {_shown(version)}; this reader supports {SUPPORTED_SNAPSHOT_VERSION}",
        )
    for key in top:
        if key not in _TOP_LEVEL:
            raise SnapshotError(key, "unknown top-level field")
    for key in sorted(_REQUIRED_TOP_LEVEL):
        _get(top, key, "")
    if _str(top["schema"], "schema") != SCHEMA:
        raise SnapshotError("schema", f"not a host snapshot: {_shown(top['schema'])}")
    collector_version = _str(top["collector_version"], "collector_version")
    collected_at = _timestamp(top["collected_at"], "collected_at")
    clock = _validate_clock(top["clock"])
    hostname, host_ref = _validate_host(top["host"])
    manifest = _validate_manifest(top["manifest"])
    sections = _validate_sections(top["sections"], manifest)
    _validate_counts(top["counts"], manifest)
    commands = _validate_receipt(top["receipt"])
    runtime = _validate_runtime(top["runtime"]) if "runtime" in top else None
    stored = _str(top["self_hash"], "self_hash")
    if not _SELF_HASH.fullmatch(stored):
        raise SnapshotError("self_hash", f"not a sha256 digest: {_shown(stored)}")
    computed = _canonical_hash(top)
    if stored != computed:
        raise SnapshotError(
            "self_hash",
            f"mismatch: the file says {stored} but its content hashes to {computed}; "
            "it was corrupted or edited after it was written",
        )

    unassessed = None
    if manifest and all(
        e.status == "unavailable" and e.reason == UNSUPPORTED_RUNTIME for e in manifest.values()
    ):
        unassessed = UNSUPPORTED_RUNTIME
    return Snapshot(
        hostname=hostname,
        host_ref=host_ref,
        collected_at=collected_at,
        collected_at_text=top["collected_at"],
        clock=clock,
        manifest=manifest,
        sections=sections,
        commands=commands,
        runtime=runtime,
        unassessed=unassessed,
        self_hash=stored,
        collector_version=collector_version,
    )


def load_file(path: Path) -> Snapshot:
    """Read a snapshot file the operator named. The size is checked before the file is read."""
    try:
        size = path.stat().st_size
        if size > MAX_BYTES:
            raise _limit("MAX_BYTES", "file", f"{size} bytes > {MAX_BYTES}")
        with path.open("rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        raise SnapshotError(
            "snapshot file", f"cannot be read ({exc.strerror or type(exc).__name__})"
        ) from None
    return parse(data)
