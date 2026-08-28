"""The one record/replay layer in `core/`.

`core/dns.py` and `core/tls.py` each grew their own fixture directory
handling, fixture naming, JSON round-trip and missing-fixture error. HTTP
needed the same thing next, and a fourth and fifth protocol (MCP, device
protocols) are coming after it. This module is what all of them share.

What is genuinely common across every protocol's record/replay backend:

- a fixture directory that is created on first write and never invented on
  read (a replay run never falls back to the wire, so a missing file is a
  hard error, not a miss to fill in)
- turning a lookup key into a filesystem-safe, collision-resistant filename
- serialising and deserialising a fixture as JSON on disk
- the shape of "this was never recorded" - one error type, one message
  template, everywhere replay can fail

What is deliberately **not** here, because forcing it into a generic shape
would be the wrong abstraction:

- **what belongs in the lookup key.** DNS keys on `(name, rrtype, resolver)`
  and deliberately preserves the resolver as part of the key, because
  collapsing two resolvers into one fixture would make an independent
  re-query a no-op on replay - see `core/dns.py`. TLS keys on
  `(host, port, servername, protocol version)`. HTTP keys on
  `(method, url)`. Each protocol decides its own key; this module only turns
  whatever key a protocol hands it into a safe filename.
- **canonicalising a value before it becomes part of the key.** DNS's
  wildcard probe uses a random label on the wire, on purpose, and canonicalises
  it away before naming the fixture so it can ever be replayed - see the
  comment by `_PROBE_LABEL` in `core/dns.py`. That is a DNS fact, not a
  general one.
- **redaction.** Only HTTP fixtures can contain a customer's secrets, so only
  the HTTP recording backend redacts before writing. DNS answers and TLS
  handshakes are recorded as the wire gave them.
- **judging a recording against time.** `CertificateInfo.days_until_expiry`
  takes a `now` so a replayed handshake is judged against when it was
  recorded, not against today. This module only has to make sure a
  protocol's own timestamp field survives the JSON round trip undisturbed -
  it stores whatever dict a protocol gives it, and gives the same dict back.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SAFE_NAME = re.compile(r"[^a-z0-9._-]")


class MissingFixtureError(LookupError):
    """A replay run asked for an interaction that was never recorded.

    Shared by every protocol so that a caller (the CLI, a corpus harness) can
    catch one error type regardless of which client raised it, rather than
    needing to know that DNS, TLS and HTTP each spell "not recorded"
    differently.
    """


def missing_fixture_message(*, kind: str, subject: str, directory: Path | str) -> str:
    """The one wording for "this was never recorded", parameterised by protocol.

    `kind` names what is missing ("answer", "handshake", "response"), and
    `subject` is the protocol's own description of what was asked for.
    """
    return (
        f"no recorded {kind} for {subject} in {directory}. "
        "Record it with --record before replaying; a replay run never "
        "falls back to the wire."
    )


def sanitize_filename_part(text: str) -> str:
    """Lowercase and replace anything that is not a safe filename character.

    Applied to the human-readable part of a fixture name - the rest of the
    name's uniqueness comes from `fixture_digest`, so this only has to be
    filesystem-safe, not collision-free on its own.
    """
    return _SAFE_NAME.sub("_", text.lower())


def fixture_digest(key: str, length: int = 10) -> str:
    """A short, stable digest of a protocol's full lookup key.

    `length` is configurable only because DNS picked 8 hex characters and TLS
    picked 10 before this module existed, and changing either now would
    rename every committed fixture silently. New protocols should use the
    default.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:length]


def fixture_filename(stem: str, *tags: str, digest: str) -> str:
    """Join an already-sanitised stem, display tags and a digest into a name.

    Tags are used verbatim, cased however the caller wants them displayed
    (`TXT`, `TLSv1_2`, `any`) - this function does not touch their case, only
    DNS and TLS's committed fixtures already disagree on it (`TXT` vs
    `TLSv1_2`), and changing either now would silently rename a committed
    fixture. They are purely cosmetic either way: the digest, not the tags,
    is what makes two different keys land in different files even when their
    tags collide.
    """
    parts = [stem, *tags, digest]
    return ".".join(parts) + ".json"


@dataclass
class FixtureStore:
    """Fixture directory handling and the JSON round trip, nothing else.

    A protocol's Recording/Replay backend owns naming and interpretation; this
    only owns the filesystem.
    """

    directory: Path

    def __post_init__(self) -> None:
        self.directory = Path(self.directory)

    def write(self, filename: str, payload: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / filename
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def read(self, filename: str) -> dict[str, Any] | None:
        """`None` when nothing was recorded - the caller decides how loud to be."""
        path = self.directory / filename
        if not path.exists():
            return None
        data: dict[str, Any] = json.loads(path.read_text())
        return data
