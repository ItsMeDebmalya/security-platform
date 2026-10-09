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

import re
import secrets
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from core.cost import CostMeter
from core.killswitch import KillSwitch
from core.replay import (
    FixtureStore,
    fixture_digest,
    fixture_filename,
    missing_fixture_message,
    sanitize_filename_part,
)
from core.replay import (
    MissingFixtureError as MissingFixtureError,
)

DEFINITE_RCODES = frozenset({"NOERROR", "NXDOMAIN", "NODATA"})
"""Answers we can reason from. Anything else means we did not find out."""

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


def _fixture_name(name: str, rrtype: str, resolver: str | None = None) -> str:
    """One file per (name, rrtype, resolver).

    The resolver is part of the key because an independent re-query through a
    second resolver is a real validation step, and a recording that collapsed
    the two would make that validation a no-op on replay. This is a DNS fact,
    not a general one, which is why the key is built here rather than in
    `core/replay.py`.

    Wildcard probes use a random label on the wire - which is the point, since
    a fixed one would be cached and could be special-cased by a target - so
    the random part is canonicalised away here. Otherwise no wildcard probe
    could ever be replayed. The recorded answer keeps the real name it used.
    """
    canonical = _PROBE_LABEL.sub(f"{WILDCARD_PROBE_PREFIX}.", name.lower().rstrip("."))
    key = f"{canonical}|{rrtype.upper()}|{resolver or ''}"
    return fixture_filename(
        sanitize_filename_part(canonical), rrtype.upper(), digest=fixture_digest(key, length=8)
    )


class FakeResolver:
    """An in-memory resolver for tests. Unknown names are NXDOMAIN.

    `by_resolver` overrides answers for one named resolver, so a test or a
    corpus case can make two resolvers disagree. Until D39 this resolver
    ignored which resolver was asked, so no corpus case could ever exercise a
    failed second-resolver validation. Answers are labelled with the resolver
    that was asked, as a real one's are.
    """

    def __init__(
        self,
        answers: dict[tuple[str, str], DnsResponse],
        *,
        by_resolver: dict[str, dict[tuple[str, str], DnsResponse]] | None = None,
    ) -> None:
        self._answers = {(n.lower(), t.upper()): r for (n, t), r in answers.items()}
        self._by_resolver = {
            upstream: {(n.lower(), t.upper()): r for (n, t), r in table.items()}
            for upstream, table in (by_resolver or {}).items()
        }
        self.calls: list[tuple[str, str]] = []
        self.routed: list[tuple[str, str, str | None]] = []

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        key = (name.lower(), rrtype.upper())
        self.calls.append(key)
        self.routed.append((*key, resolver))
        override = self._by_resolver.get(resolver or "", {})
        found = override.get(key, self._answers.get(key))
        if found is None:
            return DnsResponse(
                name=name, rrtype=rrtype.upper(), rcode="NXDOMAIN", records=[], resolver=resolver
            )
        return replace(found, resolver=resolver)


class RecordingResolver:
    """Wraps a resolver and writes every answer to disk for later replay."""

    def __init__(self, inner: Resolver, directory: str | Path) -> None:
        self._inner = inner
        self._store = FixtureStore(Path(directory))

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        response = self._inner.resolve(name, rrtype, resolver)
        self._store.write(_fixture_name(name, rrtype, resolver), response.to_dict())
        return response


class ReplayResolver:
    """Serves answers from recorded fixtures and never touches the network."""

    def __init__(self, directory: str | Path) -> None:
        self._store = FixtureStore(Path(directory))

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        data = self._store.read(_fixture_name(name, rrtype, resolver))
        if data is None:
            raise MissingFixtureError(
                missing_fixture_message(
                    kind="answer",
                    subject=f"{name} {rrtype.upper()} (resolver {resolver or 'default'})",
                    directory=self._store.directory,
                )
            )
        return DnsResponse.from_dict(data)


class SystemResolver:
    """The live resolver, via dnspython. Constructed by the CLI, never by a scanner.

    **A query directed at a resolver is sent to that resolver and no other**
    (D39). Each named upstream gets its own dnspython `Resolver` holding only
    that server, so there is no silent fallback to a different one either. A
    named resolver that fails returns its failure, labelled with its own name.
    Until 2026-10-08 one shared `Resolver` answered everything and the
    `resolver` argument only labelled the result, so the "independent
    re-query via 8.8.8.8" was asked of 1.1.1.1.

    An unnamed query uses the full list (or the system configuration) with
    dnspython's ordinary fallback, and is labelled with the server that
    actually answered, or nothing when no server did.
    """

    def __init__(self, resolvers: list[str] | None = None, timeout_s: float = 5.0) -> None:
        self._timeout_s = timeout_s
        self._default = self._build(list(resolvers or []))
        self._pinned: dict[str, Any] = {}

    def _build(self, nameservers: list[str]) -> Any:
        import dns.resolver

        built = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            built.nameservers = nameservers
        built.timeout = self._timeout_s
        built.lifetime = self._timeout_s
        return built

    def _for(self, upstream: str | None) -> Any:
        if upstream is None:
            return self._default
        if upstream not in self._pinned:
            self._pinned[upstream] = self._build([upstream])
        return self._pinned[upstream]

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        import dns.exception
        import dns.rdatatype
        import dns.resolver

        rrtype = rrtype.upper()
        started = time.monotonic()
        try:
            answer = self._for(resolver).resolve(name, rrtype, raise_on_no_answer=False)
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
            # The server that answered, never the one we hoped would.
            resolver=resolver or getattr(answer, "nameserver", None),
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
        self._exposures: Any = None
        """The scan's `core.exposure.ExposureLog`, wired in by `ScanContext`."""
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
        if self._exposures is not None:
            # ADR-029: every fresh public answer is seen, cited by a finding or not
            self._exposures.observe_dns(response)
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
