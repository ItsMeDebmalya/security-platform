"""SPF parsing, per RFC 7208.

Written as a parser rather than a regex on purpose. Regexes get three things
wrong that matter here: `include:` chains (which must be resolved recursively
to count DNS lookups), macros (`%{i}`, `%{d}` - legal inside a mechanism's
value and easy to mistake for a syntax error), and qualifiers (`+`, `-`, `~`,
`?`, where the absence of one means `+`).

The lookup count is the piece most scanners get wrong. RFC 7208 section 4.6.4
caps a policy at **10 DNS-querying terms**, and the terms that count are
`include`, `a`, `mx`, `ptr`, `exists` and `redirect`. `ip4`, `ip6` and `all`
cost nothing. Counting the ip4 terms is the classic bug, and it turns a
correct policy into a false positive.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

VERSION = "v=spf1"

DNS_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
"""Mechanisms that cost one DNS lookup each. `redirect` also costs one, but it
is a modifier rather than a mechanism, so it is counted separately."""

NO_LOOKUP_MECHANISMS = frozenset({"ip4", "ip6", "all"})

KNOWN_MECHANISMS = DNS_LOOKUP_MECHANISMS | NO_LOOKUP_MECHANISMS
KNOWN_MODIFIERS = frozenset({"redirect", "exp"})

MAX_DNS_LOOKUPS = 10

QUALIFIERS = frozenset({"+", "-", "~", "?"})

_TERM = re.compile(r"^(?P<qualifier>[+\-~?])?(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)(?P<rest>[:/].*)?$")
_MODIFIER = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)=(?P<value>.*)$")


@dataclass(frozen=True)
class SpfTerm:
    mechanism: str
    qualifier: str
    value: str | None
    raw: str

    def costs_lookup(self) -> bool:
        return self.mechanism in DNS_LOOKUP_MECHANISMS

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "qualifier": self.qualifier,
            "value": self.value,
            "raw": self.raw,
            "costs_lookup": self.costs_lookup(),
        }


@dataclass(frozen=True)
class SpfRecord:
    raw: str
    terms: list[SpfTerm] = field(default_factory=list)
    modifiers: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def redirect(self) -> str | None:
        return self.modifiers.get("redirect")

    @property
    def all_qualifier(self) -> str | None:
        """The qualifier on the `all` mechanism - the policy's default answer."""
        for term in self.terms:
            if term.mechanism == "all":
                return term.qualifier
        return None

    def direct_lookup_count(self) -> int:
        """DNS-querying terms in this record alone, not following includes."""
        count = sum(1 for term in self.terms if term.costs_lookup())
        if self.redirect:
            count += 1
        return count

    def include_targets(self) -> list[str]:
        return [t.value for t in self.terms if t.mechanism == "include" and t.value]

    def chain_targets(self) -> list[str]:
        """Everything whose SPF record must be fetched to evaluate this one."""
        targets = self.include_targets()
        if self.redirect:
            targets.append(self.redirect)
        return targets

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "valid": self.valid,
            "terms": [t.to_dict() for t in self.terms],
            "modifiers": dict(self.modifiers),
            "errors": list(self.errors),
            "all_qualifier": self.all_qualifier,
            "direct_lookup_count": self.direct_lookup_count(),
        }


def parse_spf(text: str) -> SpfRecord:
    raw = text.strip()
    tokens = raw.split()
    if not tokens or tokens[0].lower() != VERSION:
        return SpfRecord(raw=raw, errors=[f"record does not begin with {VERSION}"])

    terms: list[SpfTerm] = []
    modifiers: dict[str, str] = {}
    errors: list[str] = []

    for token in tokens[1:]:
        modifier = _MODIFIER.match(token)
        if modifier and modifier.group("name").lower() not in KNOWN_MECHANISMS:
            name = modifier.group("name").lower()
            if name in KNOWN_MODIFIERS:
                if name in modifiers:
                    errors.append(f"modifier {name}= appears more than once")
                modifiers[name] = modifier.group("value")
            # RFC 7208 6: an unrecognised modifier is ignored, not an error.
            continue

        match = _TERM.match(token)
        if match is None:
            errors.append(f"cannot parse term {token!r}")
            continue

        name = match.group("name").lower()
        if name not in KNOWN_MECHANISMS:
            errors.append(f"unknown mechanism {name!r}")
            continue

        rest = match.group("rest") or ""
        value = rest[1:] if rest.startswith(":") else (rest or None)
        term = SpfTerm(
            mechanism=name,
            qualifier=match.group("qualifier") or "+",
            value=value,
            raw=token,
        )
        errors.extend(_validate_term(term))
        terms.append(term)

    return SpfRecord(raw=raw, terms=terms, modifiers=modifiers, errors=errors)


def _validate_term(term: SpfTerm) -> list[str]:
    if term.mechanism in ("ip4", "ip6") and term.value:
        try:
            network = ipaddress.ip_network(term.value, strict=False)
        except ValueError as exc:
            return [f"{term.raw}: {exc}"]
        expected = 4 if term.mechanism == "ip4" else 6
        if network.version != expected:
            return [f"{term.raw}: address is IPv{network.version}, not IPv{expected}"]
    return []


# --- fetching and chain resolution -----------------------------------------


@dataclass(frozen=True)
class SpfLookup:
    """The result of asking one name for its SPF record."""

    domain: str
    answer: Any
    record: SpfRecord | None
    duplicate: bool
    definite: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "rcode": self.answer.rcode,
            "record": self.record.to_dict() if self.record else None,
            "duplicate_spf_records": self.duplicate,
            "definite": self.definite,
        }


def fetch_spf(domain: str, client: Any) -> SpfLookup:
    """Fetch and parse the SPF record at `domain`.

    Two things this is careful about:

    - A name usually carries several TXT records (verification tokens and so
      on). The SPF record is the one beginning `v=spf1`, and the others are
      not errors.
    - **More than one SPF record at a name is a misconfiguration**, not a
      parse failure: RFC 7208 4.5 makes the evaluation permerror. We report
      it rather than silently taking the first.
    """
    answer = client.query(domain, "TXT")
    candidates = [r for r in answer.records if r.strip().lower().startswith(VERSION)]
    record = parse_spf(candidates[0]) if candidates else None
    return SpfLookup(
        domain=domain,
        answer=answer,
        record=record,
        duplicate=len(candidates) > 1,
        definite=answer.is_definite(),
    )


@dataclass
class SpfChain:
    """The whole policy, with every name that had to be resolved to evaluate it."""

    root: str
    steps: list[SpfLookup] = field(default_factory=list)
    total_lookups: int = 0
    problems: list[str] = field(default_factory=list)
    definite: bool = True
    limit: int = MAX_DNS_LOOKUPS

    @property
    def exceeded(self) -> bool:
        return self.total_lookups > self.limit

    @property
    def root_record(self) -> SpfRecord | None:
        return self.steps[0].record if self.steps else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "steps": [step.to_dict() for step in self.steps],
            "total_lookups": self.total_lookups,
            "limit": self.limit,
            "exceeded": self.exceeded,
            "problems": list(self.problems),
            "definite": self.definite,
        }


def resolve_spf_chain(domain: str, client: Any) -> SpfChain:
    """Walk the include/redirect graph, counting DNS-querying terms.

    The count is what RFC 7208 4.6.4 caps at ten. A chain we could not finish
    walking - a SERVFAIL partway down - produces `definite=False`, because a
    count that stopped early is not a count and must not become a finding.
    """
    chain = SpfChain(root=domain)
    seen: set[str] = set()
    queue: list[str] = [domain]

    while queue:
        current = queue.pop(0)
        key = current.lower().rstrip(".")
        if key in seen:
            chain.problems.append(f"include loop: {current} is already in the chain")
            continue
        seen.add(key)

        lookup = fetch_spf(current, client)
        chain.steps.append(lookup)

        if not lookup.definite:
            chain.definite = False
            chain.problems.append(
                f"{current}: lookup returned {lookup.answer.rcode}, so the chain "
                "could not be counted"
            )
            continue

        if lookup.record is None:
            if current != domain:
                chain.problems.append(
                    f"{current}: included by the chain but publishes no SPF record, "
                    "which makes the include a permerror"
                )
            continue

        if lookup.duplicate:
            chain.problems.append(
                f"{current}: more than one SPF record published; RFC 7208 4.5 makes "
                "this a permerror"
            )
        chain.problems.extend(f"{current}: {e}" for e in lookup.record.errors)
        chain.total_lookups += lookup.record.direct_lookup_count()
        queue.extend(lookup.record.chain_targets())

    return chain
