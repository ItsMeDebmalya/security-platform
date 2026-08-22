"""The one DNS client.

Scanners never construct their own resolver. Everything goes through here, so
caching, cost accounting, the kill switch and the rate limit are guarantees
rather than habits.

Two rules this module exists to enforce:

- **A failed lookup is not a missing record.** SERVFAIL, REFUSED and timeouts
  come back as themselves. `is_definite()` is how a scanner tells "there is no
  such record" from "we could not find out", and the second one must become an
  `inconclusive` finding, never a "missing" one.
- **Wildcards are detected before anything is concluded from a name existing.**
  A zone with a TXT wildcard answers every `_dmarc.*` lookup, and a scanner
  that has not checked will report nonsense with high confidence.

Scope note: the client scopes the *resolver* it talks to, not the names it may
ask about. Passive DNS legitimately follows chains onto third-party names - an
SPF `include:` chain is exactly that - and asking a public resolver about a
name sends nothing to the target.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from core.cost import CostMeter
from core.killswitch import KillSwitch

DEFINITE_RCODES = frozenset({"NOERROR", "NXDOMAIN", "NODATA"})
"""Answers we can reason from. Anything else means we did not find out."""

_SAFE_NAME = re.compile(r"[^a-z0-9._-]")
WILDCARD_PROBE_PREFIX = "sp-wildcard-probe-"
_PROBE_LABEL = re.compile(r"^sp-wildcard-probe-[0-9a-f]+\.")


@dataclass(frozen=True)
class DnsResponse:
    name: str
    rrtype: str
    rcode: str
    records: list[str]
    ttl: int | None = None
    flags: list[str] = field(default_factory=list)
    resolver: str | None = None
    elapsed_ms: int | None = None

    def is_definite(self) -> bool:
        """Whether this answer supports a conclusion.

        NXDOMAIN is definite: the name does not exist. SERVFAIL is not.
        """
        return self.rcode in DEFINITE_RCODES

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rrtype": self.rrtype,
            "rcode": self.rcode,
            "records": list(self.records),
            "ttl": self.ttl,
            "flags": list(self.flags),
            "resolver": self.resolver,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsResponse:
        return cls(
            name=data["name"],
            rrtype=data["rrtype"],
            rcode=data["rcode"],
            records=list(data.get("records", [])),
            ttl=data.get("ttl"),
            flags=list(data.get("flags", [])),
            resolver=data.get("resolver"),
        )


class Resolver(Protocol):
    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse: ...


def join_txt_chunks(chunks: list[str]) -> str:
    """Rejoin a TXT record that the wire split into several strings.

    A TXT string is capped at 255 bytes, so a long SPF record arrives as
    several. They concatenate with no separator; treating them as separate
    records is the classic way to mis-parse a long SPF policy.

    Only the quoting is stripped, never whitespace: a space at a chunk
    boundary is part of the record and dropping it corrupts the policy.
    """
    return "".join(chunk.strip('"') for chunk in chunks)


class MissingFixtureError(LookupError):
    """A replay run asked for a query that was never recorded."""


def _fixture_name(name: str, rrtype: str, resolver: str | None = None) -> str:
    """One file per (name, rrtype, resolver).

    The resolver is part of the key because an independent re-query through a
    second resolver is a real validation step, and a recording that collapsed
    the two would make that validation a no-op on replay.

    Wildcard probes use a random label on the wire - which is the point, since
    a fixed one would be cached and could be special-cased by a target - so
    the random part is canonicalised away here. Otherwise no wildcard probe
    could ever be replayed. The recorded answer keeps the real name it used.
    """
    canonical = _PROBE_LABEL.sub(f"{WILDCARD_PROBE_PREFIX}.", name.lower().rstrip("."))
    safe = _SAFE_NAME.sub("_", canonical)
    key = f"{canonical}|{rrtype.upper()}|{resolver or ''}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:8]
    return f"{safe}.{rrtype.upper()}.{digest}.json"


class FakeResolver:
    """An in-memory resolver for tests. Unknown names are NXDOMAIN."""

    def __init__(self, answers: dict[tuple[str, str], DnsResponse]) -> None:
        self._answers = {(n.lower(), t.upper()): r for (n, t), r in answers.items()}
        self.calls: list[tuple[str, str]] = []

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        key = (name.lower(), rrtype.upper())
        self.calls.append((name.lower(), rrtype.upper()))
        found = self._answers.get(key)
        if found is None:
            return DnsResponse(name=name, rrtype=rrtype.upper(), rcode="NXDOMAIN", records=[])
        return found


class RecordingResolver:
    """Wraps a resolver and writes every answer to disk for later replay."""

    def __init__(self, inner: Resolver, directory: str | Path) -> None:
        self._inner = inner
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        response = self._inner.resolve(name, rrtype, resolver)
        path = self._dir / _fixture_name(name, rrtype, resolver)
        path.write_text(json.dumps(response.to_dict(), indent=2, sort_keys=True) + "\n")
        return response


class ReplayResolver:
    """Serves answers from recorded fixtures and never touches the network."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        path = self._dir / _fixture_name(name, rrtype, resolver)
        if not path.exists():
            raise MissingFixtureError(
                f"no recorded answer for {name} {rrtype.upper()} "
                f"(resolver {resolver or 'default'}) in {self._dir}. "
                "Record it with --record before replaying; a replay run never "
                "falls back to the wire."
            )
        return DnsResponse.from_dict(json.loads(path.read_text()))


class SystemResolver:
    """The live resolver, via dnspython. Constructed by the CLI, never by a scanner."""

    def __init__(self, resolvers: list[str] | None = None, timeout_s: float = 5.0) -> None:
        import dns.resolver

        self._resolver = dns.resolver.Resolver(configure=not resolvers)
        if resolvers:
            self._resolver.nameservers = resolvers
        self._resolver.timeout = timeout_s
        self._resolver.lifetime = timeout_s

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        import dns.exception
        import dns.rdatatype
        import dns.resolver

        rrtype = rrtype.upper()
        started = time.monotonic()
        try:
            answer = self._resolver.resolve(name, rrtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return self._empty(name, rrtype, "NXDOMAIN", started, resolver)
        except dns.resolver.NoNameservers:
            return self._empty(name, rrtype, "SERVFAIL", started, resolver)
        except dns.exception.Timeout:
            return self._empty(name, rrtype, "TIMEOUT", started, resolver)
        except dns.exception.DNSException as exc:  # pragma: no cover - defensive
            return self._empty(name, rrtype, f"ERROR:{type(exc).__name__}", started, resolver)

        records = [self._render(rrtype, item) for item in answer.rrset or []]
        return DnsResponse(
            name=name,
            rrtype=rrtype,
            rcode="NOERROR" if records else "NODATA",
            records=records,
            ttl=int(answer.rrset.ttl) if answer.rrset is not None else None,
            resolver=resolver,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _render(rrtype: str, item: object) -> str:
        if rrtype == "TXT":
            strings = getattr(item, "strings", None)
            if strings is not None:
                return join_txt_chunks([s.decode("utf-8", "replace") for s in strings])
        return str(item)

    @staticmethod
    def _empty(
        name: str, rrtype: str, rcode: str, started: float, resolver: str | None
    ) -> DnsResponse:
        return DnsResponse(
            name=name,
            rrtype=rrtype,
            rcode=rcode,
            records=[],
            resolver=resolver,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )


class DnsClient:
    def __init__(
        self,
        *,
        resolver: Resolver,
        resolvers: list[str] | None = None,
        cost: CostMeter | None = None,
        killswitch: KillSwitch | None = None,
        ratelimit: Any = None,
        scan_id: str = "local",
        org_id: str = "org_internal",
    ) -> None:
        self._resolver = resolver
        self._resolvers = resolvers or []
        self._cost = cost
        self._killswitch = killswitch
        self._ratelimit = ratelimit
        self._scan_id = scan_id
        self._org_id = org_id
        self._cache: dict[tuple[str, str, str | None], DnsResponse] = {}
        self._wildcard_probes: dict[tuple[str, str], DnsResponse] = {}

    def query(self, name: str, rrtype: str, *, resolver: str | None = None) -> DnsResponse:
        """Look a name up.

        `resolver` directs the query at a specific upstream. Answers are cached
        per resolver, so an independent re-query is never served from the
        first resolver's cache.
        """
        upstream = resolver or (self._resolvers[0] if self._resolvers else None)
        key = (name.lower().rstrip("."), rrtype.upper(), upstream)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        if self._killswitch is not None:
            self._killswitch.check(scan_id=self._scan_id, org_id=self._org_id)

        if self._ratelimit is not None and upstream:
            self._ratelimit.acquire(upstream)

        response = self._resolver.resolve(key[0], key[1], upstream)
        if self._cost is not None:
            self._cost.record_request()
        self._cache[key] = response
        return response

    def second_resolver(self) -> str | None:
        """A resolver other than the primary, for independent re-query.

        None when only one is configured: validation that cannot run reports
        `unavailable`, it does not pretend to have happened.
        """
        return self._resolvers[1] if len(self._resolvers) > 1 else None

    def has_wildcard(self, domain: str, rrtype: str) -> bool | None:
        """Whether the zone answers for names that should not exist.

        Returns None when the probe itself did not get a definite answer -
        which is `inconclusive`, not "no wildcard".
        """
        probe_name = f"sp-wildcard-probe-{secrets.token_hex(4)}.{domain.lower().rstrip('.')}"
        response = self.query(probe_name, rrtype)
        self._wildcard_probes[(domain.lower().rstrip("."), rrtype.upper())] = response
        if not response.is_definite():
            return None
        return bool(response.records)

    def wildcard_probe(self, domain: str, rrtype: str) -> DnsResponse | None:
        """The probe answer from the last `has_wildcard` call, for use as a control."""
        return self._wildcard_probes.get((domain.lower().rstrip("."), rrtype.upper()))
