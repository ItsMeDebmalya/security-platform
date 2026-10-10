"""Pure parsing of an RDAP JSON body into a structured RegistrationInfo.

No network, no I/O — this module only handles ``json``, ``dataclasses`` and
``datetime``. Callers are responsible for fetching the RDAP body.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from typing import Any, Literal

EXPIRING_WITHIN_DAYS = 30


@dataclass(frozen=True)
class RegistrationInfo:
    expiry: date | None
    registrar: str | None
    statuses: list[str]
    created: date | None
    source: str = "rdap"
    name: str | None = None
    """The record's own `ldhName`, lowercase. A registry may answer a query for a
    name under a registered domain with that domain's record (NIXI does, seen
    2026-10-10), so the record names what it is about."""


def _parse_date(raw: object) -> date | None:
    if not isinstance(raw, str) or len(raw) < 10:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


def _extract_registrar(entities: object) -> str | None:
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrar" not in roles:
            continue
        vcard_array = entity.get("vcardArray")
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            continue
        properties = vcard_array[1]
        if not isinstance(properties, list):
            continue
        for prop in properties:
            if (
                isinstance(prop, list)
                and len(prop) >= 4
                and prop[0] == "fn"
                and isinstance(prop[3], str)
            ):
                return prop[3]
    return None


def parse_rdap(json_text: str) -> RegistrationInfo:
    try:
        body: Any = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return RegistrationInfo(None, None, [], None)

    if not isinstance(body, dict):
        return RegistrationInfo(None, None, [], None)

    expiry: date | None = None
    created: date | None = None
    events = body.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            when = _parse_date(event.get("eventDate"))
            if action == "expiration" and when is not None:
                expiry = when
            elif action == "registration" and when is not None:
                created = when

    statuses_raw = body.get("status")
    statuses = (
        [s for s in statuses_raw if isinstance(s, str)] if isinstance(statuses_raw, list) else []
    )

    registrar = _extract_registrar(body.get("entities"))
    ldh = body.get("ldhName")
    name = ldh.lower().rstrip(".") if isinstance(ldh, str) and ldh.strip() else None

    return RegistrationInfo(
        expiry=expiry, registrar=registrar, statuses=statuses, created=created, name=name
    )


def expiry_verdict(
    info: RegistrationInfo, today: date
) -> Literal["expired", "expiring", "ok", "unknown"]:
    if info.expiry is None:
        return "unknown"
    delta = (info.expiry - today).days
    if delta < 0:
        return "expired"
    if delta <= EXPIRING_WITHIN_DAYS:
        return "expiring"
    return "ok"
