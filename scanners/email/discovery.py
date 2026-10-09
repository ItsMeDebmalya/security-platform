"""DMARC policy discovery: which record applies to a domain (RFC 9989 section 4.10).

RFC 9989 (May 2026) obsoletes RFC 7489 and replaces its Public Suffix List
lookup with the DNS Tree Walk: if the domain publishes no valid DMARC record,
walk up its ancestors, at most eight queries, and apply the record of its
Organizational Domain.

Until 2026-10-09 the scanner read only `_dmarc.<target>`. A subdomain whose
parent publishes DMARC was reported as `dmarc-missing`, a false claim under
both RFCs. This module answers "which record applies" once, for every check.

What it cannot do: say which record an RFC 7489 receiver applies. Those find
the Organizational Domain with a Public Suffix List, and we do not consult one.
A policy inherited from an ancestor therefore carries `inherited=True`, and
the findings built on it state both readings rather than assert one.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from core.dns import DnsResponse
from scanners.email.dmarc import VERSION, DmarcRecord, parse_dmarc

MAX_QUERIES = 8


def is_dmarc_candidate(text: str) -> bool:
    """Looks like a DMARC record, in any case. Used to *report* on what was published."""
    return text.strip().lower().startswith("v=dmarc1")


def has_exact_version(text: str) -> bool:
    """RFC 9989 4.10 step 2: a record must start with a v tag naming DMARC1, exactly."""
    first = text.strip().split(";", 1)[0]
    name, _, value = first.partition("=")
    return name.strip() == "v" and value.strip() == VERSION


@dataclass(frozen=True)
class Discovery:
    domain: str
    target_answer: DnsResponse
    target_records: int
    """How many DMARC-looking records `_dmarc.<domain>` returned. More than one
    means every one of them is discarded (RFC 7489 6.6.3, RFC 9989 4.10)."""
    record: DmarcRecord | None = None
    """The record that applies, as published. None when none applies."""
    answer: DnsResponse | None = None
    """The answer the applied record came from."""
    source: str | None = None
    """The domain the applied record is published for."""
    policy_tag: str = "p"
    """Which tag supplies the policy: `p`, or `sp`/`np` when inherited."""
    queried: list[DnsResponse] = field(default_factory=list)
    definite: bool = True
    """False when a lookup failed before the walk could conclude."""

    @property
    def inherited(self) -> bool:
        return self.source is not None and self.source != self.domain

    @property
    def effective(self) -> DmarcRecord | None:
        """The applied record with the policy this domain actually gets in `p`."""
        if self.record is None or self.policy_tag == "p":
            return self.record
        value = self.record.tags.get(self.policy_tag)
        if value is None:
            return self.record
        return replace(self.record, tags={**self.record.tags, "p": value})

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "source": self.source,
            "inherited": self.inherited,
            "policy_tag": self.policy_tag,
            "definite": self.definite,
            "target_records": self.target_records,
            "queried": [{"name": q.name, "rcode": q.rcode} for q in self.queried],
        }


def _single_valid(answer: DnsResponse) -> DmarcRecord | None:
    candidates = [r for r in answer.records if is_dmarc_candidate(r)]
    valid = [r for r in candidates if has_exact_version(r)]
    if len(candidates) != 1 or len(valid) != 1:
        return None
    return parse_dmarc(valid[0])


def _walk_names(domain: str) -> list[str]:
    labels = domain.split(".")
    labels = labels[-(MAX_QUERIES - 1) :] if len(labels) > MAX_QUERIES else labels[1:]
    return [".".join(labels[i:]) for i in range(len(labels))]


def discover(
    domain: str, dns: Any, *, author_exists: bool = True, resolver: str | None = None
) -> Discovery:
    domain = domain.lower().rstrip(".")
    target = dns.query(f"_dmarc.{domain}", "TXT", resolver=resolver)
    target_count = sum(1 for r in target.records if is_dmarc_candidate(r))
    queried = [target]
    if not target.is_definite():
        return Discovery(domain, target, 0, queried=queried, definite=False)

    own = _single_valid(target)
    if own is not None:
        return Discovery(domain, target, target_count, own, target, domain, "p", queried)

    found: list[tuple[str, DmarcRecord, DnsResponse]] = []
    for name in _walk_names(domain):
        answer = dns.query(f"_dmarc.{name}", "TXT", resolver=resolver)
        queried.append(answer)
        if not answer.is_definite():
            return Discovery(domain, target, target_count, queried=queried, definite=False)
        record = _single_valid(answer)
        if record is None:
            continue
        found.append((name, record, answer))
        if record.tags.get("psd", "").lower() in ("y", "n"):
            break

    chosen = _organizational(domain, found)
    if chosen is None:
        return Discovery(domain, target, target_count, queried=queried)
    name, record, answer = chosen
    tag = "sp" if author_exists else "np"
    if tag == "np" and "np" not in record.tags:
        tag = "sp"
    if tag not in record.tags:
        tag = "p"
    return Discovery(domain, target, target_count, record, answer, name, tag, queried)


def _organizational(
    domain: str, found: list[tuple[str, DmarcRecord, DnsResponse]]
) -> tuple[str, DmarcRecord, DnsResponse] | None:
    """RFC 9989 4.10.2, longest name to shortest (`found` is in walk order).

    1. `psd=n`: this is the Organizational Domain.
    2. `psd=y`: the Organizational Domain is one label below it. Its own
       record applies if it published one, otherwise the PSD's does
       (4.10.1: Author Domain, then Organizational Domain, then PSD).
    3. Otherwise the record with the fewest labels.
    """
    by_name = {entry[0]: entry for entry in found}
    for name, record, answer in found:
        psd = record.tags.get("psd", "").lower()
        if psd == "n":
            return name, record, answer
        if psd == "y":
            below = _one_label_below(domain, name)
            return by_name.get(below or "", (name, record, answer))
    return found[-1] if found else None


def _one_label_below(domain: str, ancestor: str) -> str | None:
    labels = domain.split(".")
    depth = len(ancestor.split("."))
    if len(labels) <= depth:
        return None
    return ".".join(labels[-(depth + 1) :])
