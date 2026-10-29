"""The collector: run each module, assemble the snapshot, redact it, write the file.

    python -m agent --output /path/to/snapshot.json

Section status comes from what the modules saw in the receipt's terms: a command that
ran and failed is an `error` section naming it, a `needs_root` refusal is `unavailable:
needs_root`, an absent file is `unavailable`, and a module that raises is an `error`
section too. Nothing is a silent pass. 3.6 floor, stdlib only.
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from agent import explain, snapshot, version
from agent.modules import Outcome, failed, host_identity, kernel, os_release, packages, ssh
from agent.readfile import FileReader
from agent.receipt import Receipt
from agent.redact import redact_tree
from agent.run import Runner

# (section, module). The order is the manifest order and must match version.SECTIONS.
MODULES = (
    ("os_release", os_release),
    ("kernel", kernel),
    ("host_identity", host_identity),
    ("packages", packages),
    ("ssh", ssh),
)

Tools = Tuple[Receipt, Runner, FileReader]


def default_tools() -> Tools:
    receipt = Receipt(collector_version=version.COLLECTOR_VERSION)
    return receipt, Runner(receipt), FileReader(receipt)


def _run_module(
    module: Any, runner: Runner, reader: FileReader, hostname: Optional[str]
) -> Outcome:
    try:
        if module is host_identity:
            out = module.collect(runner, reader, hostname=hostname)
        else:
            out = module.collect(runner, reader)
        return out  # type: ignore[no-any-return]
    except Exception as exc:  # a module bug is an error section, never a crash or a pass
        return failed("module_exception:%s" % type(exc).__name__)


def _clock() -> Dict[str, Any]:
    return {
        "source": "host",
        "tz_offset_minutes": int(time.localtime().tm_gmtoff // 60),
        "monotonic_ms": int(time.monotonic() * 1000),
    }


def collect(
    receipt: Optional[Receipt] = None,
    runner: Optional[Runner] = None,
    reader: Optional[FileReader] = None,
    hostname: Optional[str] = None,
) -> Dict[str, Any]:
    if receipt is None:
        receipt, runner, reader = default_tools()
    assert runner is not None and reader is not None
    manifest: List[Dict[str, Any]] = []
    sections: Dict[str, Any] = {}
    for name, module in MODULES:
        out = _run_module(module, runner, reader, hostname)
        if out.status == "collected":
            manifest.append(snapshot.entry(name, "collected"))
            sections[name] = out.body
        elif out.status == "unavailable":
            manifest.append(snapshot.entry(name, "unavailable", reason=out.reason))
        else:
            manifest.append(snapshot.entry(name, "error", error=out.error))
    host: Dict[str, Any] = {}
    ident = sections.get("host_identity") or {}
    host["hostname"] = ident.get("hostname", hostname)
    host["machine_id_fingerprint"] = ident.get("machine_id_fingerprint")
    if "os_release" in sections:
        host["os"] = dict(sections["os_release"])
    receipt_dict = receipt.to_dict()
    counts = receipt.counts()
    # Redaction at assembly, over everything that carries collected or caller-supplied text.
    found: Dict[str, int] = {}
    sections = redact_tree(sections, found)
    host = redact_tree(host, found)
    receipt_dict = redact_tree(receipt_dict, found)
    receipt_dict["redactions"] = found
    return snapshot.build(
        manifest,
        sections,
        counts,
        host=host,
        collected_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        clock=_clock(),
        receipt=receipt_dict,
    )


def _write(path: str, text: str) -> None:
    """Write beside the target then rename into place, mode 0600; never a half file."""
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _explain(path: str) -> int:
    """Render a written snapshot's receipt as plain text. Reads that one file only."""
    try:
        with open(path, encoding="utf-8") as fh:
            snap = json.load(fh)
        receipt = snap["receipt"]
        if not isinstance(receipt, dict) or "commands" not in receipt:
            raise KeyError("receipt")
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write("%s is not a collector snapshot with a receipt\n" % path)
        return 1
    sys.stdout.write(explain.render_receipt(receipt))
    return 0


def main(argv: Optional[Sequence[str]] = None, tools: Optional[Callable[[], Tools]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agent", add_help=False)
    parser.add_argument("--output")
    parser.add_argument("--explain", metavar="SNAPSHOT")
    parser.add_argument("--explain-plan", action="store_true")
    args, _unknown = parser.parse_known_args(sys.argv[1:] if argv is None else list(argv))
    if args.explain_plan:  # prints the allowlists; runs nothing, opens nothing
        sys.stdout.write(explain.render_plan())
        return 0
    if args.explain:
        return _explain(args.explain)
    if not args.output:
        sys.stderr.write("no output path; pass --output PATH (nothing is written to stdout)\n")
        return 2
    receipt, runner, reader = (tools or default_tools)()
    snap = collect(receipt, runner, reader)
    try:
        _write(args.output, snapshot.dumps(snap))
    except OSError as exc:
        sys.stderr.write("could not write %s: %s\n" % (args.output, exc.strerror or exc))
        return 1
    c = snap["counts"]
    sys.stderr.write(
        "wrote %s: %d collected, %d unavailable, %d error\n"
        % (args.output, c["sections_collected"], c["sections_unavailable"], c["sections_error"])
    )
    return 0
