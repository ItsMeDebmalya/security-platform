"""Evidence capture, redaction and export.

**Redact before storage, never before display.** By the time a body reaches
disk the secrets are already gone, so there is no window in which we hold a
customer's session token.

Evidence is replayable: every `http_pair` exports as curl, which is what makes
Request Replay nearly free later.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from core.dns import DnsResponse
from core.models import (
    DnsAnswerEvidence,
    DnsAnswerRecords,
    DnsExchange,
    DnsQuery,
    HttpExchange,
    HttpPairEvidence,
    HttpRequest,
    HttpResponse,
)

REDACTED = "[redacted]"
DEFAULT_BODY_CAP = 262_144
"""256 KB. Beyond it we keep the head and the tail and mark the gap."""

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "api-key",
    }
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)


def redact_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Replace sensitive header values. Returns the headers and what was hit."""
    cleaned: dict[str, str] = {}
    hit: list[str] = []
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            cleaned[key] = REDACTED
            hit.append(key.lower())
        else:
            cleaned[key] = value
    return cleaned, hit


def redact_body(body: str | None) -> tuple[str | None, list[str]]:
    """Replace anything matching a secret pattern in a body."""
    if not body:
        return body, []
    hit: list[str] = []
    for name, pattern in SECRET_PATTERNS:
        body, count = pattern.subn(f"{REDACTED}:{name}", body)
        if count:
            hit.append(name)
    return body, hit


def truncate_body(body: str | None, cap: int = DEFAULT_BODY_CAP) -> tuple[str | None, bool]:
    """Cap a body at `cap` bytes, keeping the head and the tail.

    The middle is replaced by an explicit marker: a silently shortened body
    would make evidence misleading rather than merely incomplete.
    """
    if body is None or len(body) <= cap:
        return body, False
    head = cap // 2
    tail = cap - head
    omitted = len(body) - cap
    return f"{body[:head]}\n... [{omitted} bytes truncated] ...\n{body[-tail:]}", True


def _capture_request(raw: dict[str, Any], cap: int) -> tuple[HttpRequest, list[str]]:
    headers, header_hits = redact_headers(raw.get("headers") or {})
    body, body_hits = redact_body(raw.get("body"))
    body, truncated = truncate_body(body, cap)
    return (
        HttpRequest(
            method=raw["method"],
            url=raw["url"],
            headers=headers,
            body=body,
            body_truncated=truncated,
        ),
        header_hits + body_hits,
    )


def _capture_response(raw: dict[str, Any], cap: int) -> tuple[HttpResponse, list[str]]:
    headers, header_hits = redact_headers(raw.get("headers") or {})
    body, body_hits = redact_body(raw.get("body"))
    body, truncated = truncate_body(body, cap)
    return (
        HttpResponse(
            status=raw["status"],
            headers=headers,
            body=body,
            body_truncated=truncated,
            elapsed_ms=raw.get("elapsed_ms"),
        ),
        header_hits + body_hits,
    )


def capture_http_pair(
    *,
    label: str,
    control_request: dict[str, Any],
    control_response: dict[str, Any],
    test_request: dict[str, Any],
    test_response: dict[str, Any],
    delta: dict[str, str] | None = None,
    payload_id: str | None = None,
    cap: int = DEFAULT_BODY_CAP,
) -> HttpPairEvidence:
    """Build control-vs-test HTTP evidence, redacted and size-capped."""
    redactions: list[str] = []
    pieces = []
    for raw_req, raw_resp in ((control_request, control_response), (test_request, test_response)):
        request, request_hits = _capture_request(raw_req, cap)
        response, response_hits = _capture_response(raw_resp, cap)
        redactions.extend(request_hits + response_hits)
        pieces.append(HttpExchange(request=request, response=response))

    return HttpPairEvidence(
        kind="http_pair",
        label=label,
        control=pieces[0],
        test=pieces[1],
        delta=delta or {},
        payload_id=payload_id,
        captured_at=datetime.now(UTC),
        redactions=sorted(set(redactions)),
    )


def to_curl(request: HttpRequest) -> str:
    """Export a captured request as a runnable curl command.

    Redacted values stay redacted: the command shows the user what we sent,
    and their own credentials are theirs to re-supply.
    """
    parts = [f"curl -X {request.method}", f"'{request.url}'"]
    for key, value in request.headers.items():
        parts.append(f"-H '{key}: {value}'")
    if request.body:
        parts.append(f"--data-raw '{request.body}'")
    return " ".join(parts)


def _exchange(answer: DnsResponse) -> DnsExchange:
    return DnsExchange(
        query=DnsQuery(name=answer.name, rrtype=answer.rrtype, resolver=answer.resolver),
        answer=DnsAnswerRecords(
            rcode=answer.rcode,
            records=list(answer.records),
            ttl=answer.ttl,
            flags=list(answer.flags),
        ),
    )


def dns_evidence(
    *,
    label: str,
    test: DnsResponse,
    control: DnsResponse | None,
    control_rationale: str,
) -> DnsAnswerEvidence:
    """Build DNS evidence.

    The usual control is a random-label probe proving the zone has no wildcard.
    Where no control is possible the rationale must say why - "we did not
    bother" is not an acceptable answer, so an empty rationale is refused.
    """
    if not control_rationale.strip():
        raise ValueError(
            "dns evidence needs a control_rationale explaining what the control is, "
            "or why none is possible"
        )
    return DnsAnswerEvidence(
        kind="dns_answer",
        label=label,
        test=_exchange(test),
        control=_exchange(control) if control is not None else None,
        control_rationale=control_rationale,
        captured_at=datetime.now(UTC),
    )
