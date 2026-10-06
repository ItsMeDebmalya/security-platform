"""Anti-bot interstitials and edge blocks.

A challenge page answered instead of the site must never be judged as the
site: every check that reads it becomes inconclusive (waf_block), and it is
never fingerprinted as the customer's stack. Signatures here are confirmed
against a real recording only when one exists (ledger D-W2).
"""

from __future__ import annotations

from collections.abc import Mapping

from scanners.web.headers import get


def detect(status: int, headers: Mapping[str, str], body: str) -> str | None:
    # https://developers.cloudflare.com/cloudflare-challenges/
    # challenge-types/challenge-pages/detect-response/
    if (get(headers, "cf-mitigated") or "").strip().lower() == "challenge":
        return "Cloudflare challenge"
    if status in (403, 503) and "/cdn-cgi/challenge-platform/" in (body or ""):
        return "Cloudflare challenge"
    server = (get(headers, "server") or "").lower()
    if (
        status == 403
        and server.startswith("akamaighost")
        and "access denied" in (body or "").lower()
    ):
        return "Akamai edge block"
    return None
