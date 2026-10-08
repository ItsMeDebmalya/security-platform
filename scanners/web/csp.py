"""Content-Security-Policy parsing and script-policy grading.

Presence is not protection: a CSP with 'unsafe-inline' is close to worthless
(docs/05-phase-1-first-tools.md, Tool 4 gotchas). Multiple policies are all
enforced, so a weakness counts only if every policy permits it.

CSP3 note: 'strict-dynamic' neutralises host/scheme sources (*, http:, https:,
data:) by instructing browsers to ignore them; they are backward-compat fallbacks
and do not expose weaknesses when strict-dynamic is present.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import reduce

ALL_WEAKNESSES = frozenset(
    {"unsafe-inline", "unsafe-eval", "wildcard", "scheme-http", "scheme-data"}
)
_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


@dataclass(frozen=True)
class Policy:
    directives: dict[str, tuple[str, ...]]


def parse(value: str | None) -> list[Policy]:
    if not value:
        return []
    policies: list[Policy] = []
    for chunk in value.split(","):
        directives: dict[str, tuple[str, ...]] = {}
        for part in chunk.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if name not in directives:  # CSP3: the first occurrence wins
                directives[name] = tuple(t.lower() for t in tokens[1:])
        if directives:
            policies.append(Policy(directives))
    return policies


def script_sources(policy: Policy) -> tuple[str, ...] | None:
    if "script-src" in policy.directives:
        return policy.directives["script-src"]
    return policy.directives.get("default-src")


def weaknesses(policy: Policy) -> frozenset[str]:
    sources = script_sources(policy)
    if sources is None:
        return ALL_WEAKNESSES
    has_strict_dynamic = "'strict-dynamic'" in sources
    exempt_inline = has_strict_dynamic or any(s.startswith(_NONCE_OR_HASH) for s in sources)
    found: set[str] = set()
    if "'unsafe-inline'" in sources and not exempt_inline:
        found.add("unsafe-inline")
    if "'unsafe-eval'" in sources:
        found.add("unsafe-eval")
    # Schemes and wildcard are ignored when strict-dynamic is present
    if not has_strict_dynamic:
        if "*" in sources:
            found.add("wildcard")
        if "http:" in sources:
            found.add("scheme-http")
        if "data:" in sources:
            found.add("scheme-data")
    return frozenset(found)


def effective_weaknesses(policies: list[Policy]) -> frozenset[str]:
    if not policies:
        return frozenset()
    return reduce(lambda a, b: a & b, (weaknesses(p) for p in policies))


def restricts_scripts(policies: list[Policy]) -> bool:
    return any(script_sources(p) is not None for p in policies)


def has_frame_ancestors(policies: list[Policy]) -> bool:
    return any("frame-ancestors" in p.directives for p in policies)
