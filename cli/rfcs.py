"""RFC currency check: every RFC a scanner cites must still be current.

ADR-017 (amended 2026-10-08). The DMARC checks were built from RFC 7489 five
months after RFC 9989 obsoleted it, and nothing noticed (ledger D44). This
reads every `rfc-editor.org/rfc/rfcNNNN` URL in `scanners/` and asks the RFC
Editor's own metadata (`https://www.rfc-editor.org/rfc/rfcNNNN.json`) whether
it has been obsoleted. That is the primary source, the same data behind the
"Obsoleted by" line on each RFC's info page.

It needs the network, so it is a separate `make rfc-check`, not part of
`make test`. A failure is a reason to re-read the newer RFC, not an
instruction to change a URL.

**Legacy but deployed** (operator, 2026-10-09). An obsoleted RFC can still be
the right citation, when the check is about behaviour that is still deployed:
TLS 1.2 connections, or today's CT logs. Such an RFC is listed in
`tools/rfc-exemptions.yaml` with a written reason, the successor that was read,
and evidence. It is then reported as exempt rather than failing. An exemption
without its reason is refused, and `tests/cli/test_rfcs.py` checks that offline,
so a missing reason fails CI even though this network check does not run there.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CITATION = re.compile(r"rfc-editor\.org/rfc/rfc(\d+)")
EXEMPTIONS_PATH = ROOT / "tools" / "rfc-exemptions.yaml"
_REQUIRED = ("reason", "successor_checked", "evidence")


def parse_exemptions(entries: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """RFC number -> its exemption. Each needs a reason, the successor read, and evidence."""
    out: dict[int, dict[str, Any]] = {}
    for entry in entries:
        number = int(entry["rfc"])
        missing = [k for k in _REQUIRED if not str(entry.get(k) or "").strip()]
        if missing:
            raise ValueError(f"RFC {number}: an exemption needs {', '.join(missing)}")
        out[number] = entry
    return out


def load_exemptions(path: Path = EXEMPTIONS_PATH) -> dict[int, dict[str, Any]]:
    if not path.exists():
        return {}
    return parse_exemptions(list(yaml.safe_load(path.read_text()) or []))


def cited_rfcs(root: Path = ROOT / "scanners") -> dict[int, set[str]]:
    """RFC number -> the files that cite it."""
    found: dict[int, set[str]] = {}
    for path in sorted(root.rglob("*.py")):
        for number in CITATION.findall(path.read_text()):
            found.setdefault(int(number), set()).add(str(path.relative_to(ROOT)))
    return found


def obsoleted_by(number: int) -> list[str]:
    url = f"https://www.rfc-editor.org/rfc/rfc{number}.json"
    with urllib.request.urlopen(url, timeout=20) as response:
        return list(json.load(response).get("obsoleted_by") or [])


def main() -> int:
    stale = 0
    exempt = 0
    exemptions = load_exemptions()
    cited = cited_rfcs()
    for number, files in sorted(cited.items()):
        successors = obsoleted_by(number)
        if not successors:
            continue
        where = ", ".join(sorted(files))
        if number in exemptions:
            exempt += 1
            print(
                f"RFC {number} is obsoleted by {', '.join(successors)}, exempt "
                f"(legacy but deployed): {exemptions[number]['reason']} [{where}]"
            )
            continue
        stale += 1
        print(f"RFC {number} is obsoleted by {', '.join(successors)}: {where}")
    print(f"rfc check: {len(cited)} cited RFCs, {stale} obsoleted, {exempt} exempt")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
