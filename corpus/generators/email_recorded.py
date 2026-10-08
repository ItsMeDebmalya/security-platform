"""Corpus cases built from real resolver answers, where real resolvers disagreed.

ADR-027: a fixture may stand in for a real service only on recorded evidence.
Every answer written here is one that a named public resolver actually gave,
labelled with that resolver. The source is the archived disagreement
measurement of email live run 1 (2026-10-08), the first pass:
`corpus/crosscheck/email-live/2026-10-08/disagreement.json`. There, each of
1,245 lookups was asked of 1.1.1.1, 8.8.8.8 and 9.9.9.9 one at a time.

Only the resolver *order* is chosen per case. That choice decides which
resolver is primary and which validates. Nothing is invented: a lookup the
archive does not hold raises an error instead of defaulting to NXDOMAIN.

Re-run after changing which names the scanner queries:

    uv run python -m corpus.generators.email_recorded
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from core.context import ScanContext
from core.dns import WILDCARD_PROBE_PREFIX, DnsClient, DnsResponse, RecordingResolver
from core.models import Asset
from scanners.email import EmailScanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus" / "fixtures" / "email"
ARCHIVE = ROOT / "corpus" / "crosscheck" / "email-live" / "2026-10-08" / "disagreement.json"
_PROBE = re.compile(rf"^{WILDCARD_PROBE_PREFIX}[0-9a-f]+\.")

# case id -> (domain, resolver order). The first resolver is primary, the second validates.
CASES = {
    # 8.8.8.8 served icicibank.com's TXT set without its SPF record (19 strings
    # instead of 22). As primary it makes `spf-missing` look true; 1.1.1.1, as
    # the validating resolver, still has the record, so validation must fail.
    "disagree-stale-spf": ("icicibank.com", ["8.8.8.8", "1.1.1.1"]),
    # 9.9.9.9 still served a DKIM key at s1._domainkey.flipkart.com that 1.1.1.1
    # and 8.8.8.8 answered NODATA for. As primary it adds a selector that no
    # longer exists; the weak-key claim rests on mandrill, which every
    # resolver agrees on, so it must still validate.
    "disagree-stale-dkim": ("flipkart.com", ["9.9.9.9", "1.1.1.1"]),
}


class ArchiveResolver:
    """Answers only what the named resolver was recorded answering."""

    def __init__(self, domain: str) -> None:
        archive = json.loads(ARCHIVE.read_text())
        self._answers: dict[tuple[str, str, str], DnsResponse] = {}
        for key, entry in archive.items():
            owner, name, rrtype = key.split("|")
            if owner != domain:
                continue
            for upstream, (rcode, records) in entry["first"].items():
                canonical = _PROBE.sub(WILDCARD_PROBE_PREFIX, name)
                self._answers[(canonical, rrtype, upstream)] = DnsResponse(
                    name=name, rrtype=rrtype, rcode=rcode, records=list(records), resolver=upstream
                )

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        canonical = _PROBE.sub(WILDCARD_PROBE_PREFIX, name.lower().rstrip("."))
        key = (canonical, rrtype.upper(), resolver or "")
        if key not in self._answers:
            raise KeyError(f"no recorded answer from {resolver} for {name} {rrtype}")
        return self._answers[key]


def generate() -> None:
    for case_id, (domain, resolvers) in CASES.items():
        directory = FIXTURES / case_id
        if directory.exists():
            shutil.rmtree(directory)
        ctx = ScanContext(
            dns=DnsClient(
                resolver=RecordingResolver(ArchiveResolver(domain), directory), resolvers=resolvers
            ),
            progress=lambda message, fraction: None,
        )
        result = EmailScanner().run(Asset(type="domain", value=domain), "standard", ctx)
        for f in result.findings:
            print(f"{case_id:<22} {f.check_id:<20} {f.state:<14} {f.validation.outcome}")


if __name__ == "__main__":
    generate()
