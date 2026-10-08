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
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CITATION = re.compile(r"rfc-editor\.org/rfc/rfc(\d+)")


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
    for number, files in sorted(cited_rfcs().items()):
        successors = obsoleted_by(number)
        if successors:
            stale += 1
            print(
                f"RFC {number} is obsoleted by {', '.join(successors)}: {', '.join(sorted(files))}"
            )
    print(f"rfc check: {len(cited_rfcs())} cited RFCs, {stale} obsoleted")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
