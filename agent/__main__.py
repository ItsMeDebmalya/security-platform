# Entry shim. Deliberately Python 2.7 syntax: no annotations, no f-strings, no
# keyword-only arguments, so an interpreter below the floor can still parse it
# and write a valid unsupported_runtime snapshot (spec 3.3) instead of dying
# with a SyntaxError. It checks the interpreter and the platform and nothing else.
import hashlib
import io
import json
import socket
import sys
import time

try:
    from agent import version
except ImportError:  # run as `python agent/` rather than `python -m agent`
    import version


def _arg(name, default=None):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def _os_release():
    try:
        with io.open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _hash(snap):
    body = dict(snap)
    body["self_hash"] = None
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def unsupported_snapshot(found, executable):
    """A valid snapshot in which every declared section is unavailable."""
    required = ".".join(str(p) for p in version.FLOOR)
    manifest = [
        {"section": s, "status": "unavailable", "reason": "unsupported_runtime"}
        for s in version.SECTIONS
    ]
    counts = dict(
        (k, 0)
        for k in (
            "commands_run",
            "commands_refused",
            "commands_failed",
            "files_read",
            "files_refused",
            "bytes_read",
            "sections_collected",
            "sections_error",
        )
    )
    counts["sections_unavailable"] = len(manifest)
    runtime = {
        "found": found,
        "executable": executable,
        "required": required,
        "searched": list(version.SEARCHED),
    }
    snap = {
        "snapshot_version": version.SNAPSHOT_VERSION,
        "schema": version.SCHEMA,
        "collector_version": version.COLLECTOR_VERSION,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "clock": {"source": "host"},
        "host": {"hostname": socket.gethostname(), "os_release_text": _os_release()},
        "manifest": manifest,
        "sections": {},
        "runtime": runtime,
        "receipt": {"interpreter": runtime},
        "self_hash": None,
        "counts": counts,
    }
    snap["self_hash"] = _hash(snap)
    return snap


def main():
    found = _arg("--simulate-version") or ".".join(str(p) for p in sys.version_info[:3])
    platform = _arg("--simulate-platform") or sys.platform
    if not platform.startswith("linux"):
        sys.stderr.write("the collector supports Linux only; no snapshot written\n")
        return 2
    parts = [int(p) for p in found.split(".")[:2]]
    if tuple(parts) < tuple(version.FLOOR):
        out = _arg("--output")
        if not out:
            sys.stderr.write(
                "unsupported Python %s; need %s+ (pass --output)\n"
                % (found, ".".join(str(p) for p in version.FLOOR))
            )
            return 2
        snap = unsupported_snapshot(found, sys.executable)
        text = json.dumps(snap, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        with io.open(out, "w", encoding="utf-8") as fh:
            fh.write(text if not isinstance(text, bytes) else text.decode("utf-8"))
        sys.stderr.write("unsupported Python %s; wrote unsupported_runtime snapshot\n" % found)
        return 3
    from agent import collect

    return collect.main()


if __name__ == "__main__":
    sys.exit(main())
