"""DNSSEC delegation-state reasoning (pure).

Reasons over two already-fetched `DnsResponse` answers (DS at the parent, and
DNSKEY at the child) into a delegation state. No network, no I/O — the caller
is responsible for fetching both records via `core.dns`.

Per spec §10.2:

- Either answer not `is_definite()` -> `"inconclusive"`: we did not find out,
  so we do not guess.
- DS present and DNSKEY present -> `"signed"`. Full chain-of-trust validation
  (RRSIG verification against a validating resolver) is out of Light scope,
  so we do not attempt to distinguish a genuinely valid signature from a
  broken one here; `"bogus"` in that stronger sense is reserved for a future
  validating path.
- DS empty and DNSKEY empty (both definite) -> `"insecure"`: no delegation
  signal and no key served, an unsigned zone.
- DS present, DNSKEY absent (both definite) -> `"bogus"`: the parent
  delegates trust to a key the child does not serve. That is a broken
  delegation, not merely "unsigned".
- DS absent, DNSKEY present (both definite): a served key with no DS record
  at the parent is not a secure delegation — nothing anchors it to the chain
  of trust, so a resolver treats the zone as unsigned. We report
  `"insecure"` rather than inventing a fifth state for it.
"""

from __future__ import annotations

from typing import Literal

from core.dns import DnsResponse

DnssecState = Literal["signed", "insecure", "bogus", "inconclusive"]


def dnssec_state(ds: DnsResponse, dnskey: DnsResponse) -> DnssecState:
    if not ds.is_definite() or not dnskey.is_definite():
        return "inconclusive"

    has_ds = bool(ds.records)
    has_dnskey = bool(dnskey.records)

    if has_ds and has_dnskey:
        return "signed"
    if not has_ds and not has_dnskey:
        return "insecure"
    if has_ds and not has_dnskey:
        return "bogus"
    return "insecure"
