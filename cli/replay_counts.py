"""What a run counted, and under what conditions (D64).

A recorded lab scan replayed through `scan run --replay` reported 4 requests
against 6 live, with the same findings. Both numbers are honest. The two
missing ones are the D60 address pin's A and AAAA lookups: a replay backend
says `connects is False`, so `HttpClient` skips `pin()` entirely - it opens
no socket, so it needs no address - and the two `DnsClient.query` calls that
a live run pays for never happen. The recording is complete; the fixture
directory holds all six interactions.

So the recording is not at fault and the replay is not wrong. The defect is
that one published figure, `telemetry.requests`, silently meant two
different things depending on run mode, and nothing in the artefact recorded
which one it was. Making the replay perform the pin to match the number
would be the wrong repair twice over: it would do work for no reason, and it
would make every replay depend on DNS fixtures existing, breaking replays of
recordings made before D60.

The repair is to say which is which. A recorded run writes a manifest beside
its fixtures holding what it counted, **broken down by protocol** - a single
total would carry the `requests` field's own conflation of DNS lookups and
HTTP sends (D65) into a new place. A replay reads it, reports both totals and
names the difference. With no manifest, a replay says what it did and
invents no live number.

This layer is deliberately in `cli/`. The count it describes is
`core.cost.CostMeter.requests`, which is reported through `Telemetry` in the
frozen `contracts/`, so splitting that field is a migration, not an edit
(D65). Until then the breakdown lives here, next to the record/replay
wiring that causes the divergence - and when the migration comes, the
manifest already holds the data it needs.

The counters wrap the backends `cli.main._execute` wires, and are defined to
agree with the cost meter rather than with the wire: a handshake the address
policy stopped costs no request (review of D60, round 2), so it is not
counted here either. Anything the meter charges that no counter sees - the
testssl.sh connection budget, which is a fixed charge rather than a counted
call - shows up as unattributed in the reported line, which is the honest
answer and the whole point of the change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MANIFEST = "manifest.json"
"""Written beside the fixtures by a recorded run. Not a fixture itself: a
protocol never looks for it, and its absence is never an error."""

VERSION = 1


@dataclass
class Counts:
    """Interactions counted, by protocol, as the cost meter counts them."""

    http: int = 0
    dns: int = 0
    tls: int = 0

    def as_dict(self) -> dict[str, int]:
        return {"http_sends": self.http, "dns_queries": self.dns, "tls_handshakes": self.tls}


# What each counter is called in a sentence, singular protocol name included so
# the reported line reads as English rather than as field names.
_LABELS = {"http": "HTTP sends", "dns": "DNS queries", "tls": "TLS handshakes"}

_PIN = "the address pin a replay does not need"
"""Why a live run has more DNS queries than its replay. Stated only for DNS,
and only as the reason for that one difference (D60, D64)."""


@dataclass
class LiveManifest:
    counts: Counts = field(default_factory=Counts)
    requests_counted: int = 0
    """`telemetry.requests` as the live run reported it: the meter's own total,
    so it is comparable with the replay's."""


# --- the counters ------------------------------------------------------------


class _CountingHttpBackend:
    """Counts sends. Everything else is the inner backend's, unchanged."""

    def __init__(self, inner: Any, counts: Counts) -> None:
        self._inner = inner
        self._counts = counts

    @property
    def connects(self) -> bool:
        # Silence means connecting, through this wrapper too (fail closed).
        return bool(getattr(self._inner, "connects", True))

    def send(self, method: str, url: str, **kwargs: Any) -> Any:
        raw = self._inner.send(method, url, **kwargs)
        # After the call, like the meter: a send that raised cost no request.
        self._counts.http += 1
        return raw

    def record_refusal(self, *args: Any, **kwargs: Any) -> None:
        """D60: a refusal must still reach a recording, so its replay refuses
        too. It opens no socket and costs no request, so it is not counted."""
        record = getattr(self._inner, "record_refusal", None)
        if record is not None:
            record(*args, **kwargs)


class _CountingResolver:
    def __init__(self, inner: Any, counts: Counts) -> None:
        self._inner = inner
        self._counts = counts

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> Any:
        answer = self._inner.resolve(name, rrtype, resolver)
        self._counts.dns += 1
        return answer


class _CountingTlsBackend:
    def __init__(self, inner: Any, counts: Counts) -> None:
        self._inner = inner
        self._counts = counts

    @property
    def connects(self) -> bool:
        return bool(getattr(self._inner, "connects", True))

    def handshake(self, host: str, port: int, servername: str | None, **kwargs: Any) -> Any:
        raw = self._inner.handshake(host, port, servername, **kwargs)
        # The same predicate the meter uses, imported rather than restated:
        # two spellings of "this refusal costs no request" is how the live and
        # replay counts came to disagree in the first place.
        from core.tls import _stopped_by_policy

        if not _stopped_by_policy(raw):
            self._counts.tls += 1
        return raw

    def record_refusal(self, *args: Any, **kwargs: Any) -> None:
        record = getattr(self._inner, "record_refusal", None)
        if record is not None:
            record(*args, **kwargs)

    def record(self, *args: Any, **kwargs: Any) -> None:
        record = getattr(self._inner, "record", None)
        if record is not None:
            record(*args, **kwargs)


def counting_http_backend(inner: Any, counts: Counts) -> Any:
    return _CountingHttpBackend(inner, counts)


def counting_resolver(inner: Any, counts: Counts) -> Any:
    return _CountingResolver(inner, counts)


def counting_tls_backend(inner: Any, counts: Counts) -> Any:
    return _CountingTlsBackend(inner, counts)


# --- the manifest ------------------------------------------------------------


def write_manifest(directory: Path, *, counts: Counts, requests_counted: int) -> None:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": VERSION,
        "live": {**counts.as_dict(), "requests_counted": requests_counted},
        "note": (
            "What the recorded run counted. `requests_counted` is "
            "telemetry.requests, which conflates these protocols in one total "
            "(D65); the breakdown is what it was made of. A replay of these "
            "fixtures counts fewer, because it performs no address pin (D64)."
        ),
    }
    (directory / MANIFEST).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_manifest(directory: Path | None) -> LiveManifest | None:
    """`None` means "no live count is known for these fixtures" - an older
    recording, or one we cannot read. Never an error: a replay must still run,
    and it then claims nothing about a live count."""
    if directory is None:
        return None
    path = Path(directory) / MANIFEST
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if data.get("version") != VERSION:
            return None
        live = data["live"]
        return LiveManifest(
            counts=Counts(
                http=int(live["http_sends"]),
                dns=int(live["dns_queries"]),
                tls=int(live["tls_handshakes"]),
            ),
            requests_counted=int(live["requests_counted"]),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None


# --- the reported line -------------------------------------------------------


def divergence_note(
    *, replay_total: int, replay_counts: Counts, manifest: LiveManifest | None
) -> str:
    """The summary line's request clause for a replay run.

    It always says what the replay did. It says what the live run did only
    when the fixtures record it, and names each protocol the two disagree
    about, plus any remainder no counter accounts for.
    """
    if manifest is None:
        return f"{replay_total} request(s) replayed (no live count recorded with these fixtures)"

    live = manifest.requests_counted
    parts: list[str] = []
    attributed = 0
    for name, label in _LABELS.items():
        delta = getattr(manifest.counts, name) - getattr(replay_counts, name)
        if delta > 0:
            reason = f" - {_PIN}" if name == "dns" else ""
            parts.append(f"{delta} more {label}{reason}")
        elif delta < 0:
            parts.append(f"{-delta} fewer {label} live")
        attributed += delta

    remainder = (live - replay_total) - attributed
    if remainder:
        word = "more" if remainder > 0 else "fewer"
        parts.append(f"{abs(remainder)} {word} not attributed to a counted protocol")

    if not parts:
        return f"{replay_total} request(s) replayed ({live} live: the same count)"
    return f"{replay_total} request(s) replayed ({live} live: {', '.join(parts)})"
