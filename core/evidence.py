"""Evidence capture, redaction and export.

**Redact before storage, never before display.** By the time a body reaches
disk the secrets are already gone, so there is no window in which we hold a
customer's session token. The redactor itself is `core/redaction.py`
(ADR-028); this module applies it to every capture: URLs, header names and
values, bodies, DNS records and certificate strings.

Evidence is replayable: every `http_pair` exports as curl, which is what makes
Request Replay nearly free later.
"""

from __future__ import annotations

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
    RedactionReceipt,
    TlsHandshakeEvidence,
)
from core.redaction import REDACTED as REDACTED  # re-exported: scanners import it from here
from core.redaction import SECRET_PATTERNS as SECRET_PATTERNS
from core.redaction import SENSITIVE_HEADERS as SENSITIVE_HEADERS
from core.redaction import (
    Counts,
    Receipts,
    add_receipts,
    cap_text,
    receipt_list,
    receipts_from,
    redact_header_map,
    redact_text,
)

DEFAULT_BODY_CAP = 262_144
"""256 KB. Beyond it we keep the head and the tail and mark the gap."""


def redact_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Redact headers by name *and* by value (ADR-028, ledger D21).

    A header on `SENSITIVE_HEADERS` is replaced whole. Every other header has
    its name and value run through the redactor: a secret in `Server:` or
    `X-Powered-By:` is a secret all the same.
    """
    counts: dict[str, int] = {}
    cleaned = redact_header_map(headers, counts)
    return cleaned, list(counts)


def redact_body(body: str | None) -> tuple[str | None, list[str]]:
    """Remove secrets from a body: token patterns and whole private-key blocks."""
    body, counts = redact_text(body)
    return body, list(counts)


def truncate_body(body: str | None, cap: int = DEFAULT_BODY_CAP) -> tuple[str | None, bool]:
    """Cap a body at `cap` bytes, keeping the head and the tail.

    It redacts first (ADR-028 clause 4), so truncation can never split a
    secret and leave part of it behind. The middle is replaced by an explicit
    marker: a silently shortened body would make evidence misleading rather
    than merely incomplete.
    """
    return cap_text(body, cap)


def _capture_request(raw: dict[str, Any], cap: int) -> tuple[HttpRequest, dict[str, Counts]]:
    header_counts: Counts = {}
    headers = redact_header_map(raw.get("headers") or {}, header_counts)
    body, body_counts = redact_text(raw.get("body"))
    body, truncated = truncate_body(body, cap)
    url, url_counts = redact_text(raw["url"])
    return (
        HttpRequest(
            method=raw["method"],
            url=url or raw["url"],
            headers=headers,
            body=body,
            body_truncated=truncated,
        ),
        {"url": url_counts, "headers": header_counts, "body": body_counts},
    )


def _capture_response(raw: dict[str, Any], cap: int) -> tuple[HttpResponse, dict[str, Counts]]:
    header_counts: Counts = {}
    headers = redact_header_map(raw.get("headers") or {}, header_counts)
    body, body_counts = redact_text(raw.get("body"))
    body, truncated = truncate_body(body, cap)
    return (
        HttpResponse(
            status=raw["status"],
            headers=headers,
            body=body,
            body_truncated=truncated,
            elapsed_ms=raw.get("elapsed_ms"),
        ),
        {"headers": header_counts, "body": body_counts},
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
    """Build control-vs-test HTTP evidence, redacted and size-capped.

    A response that is an `HttpClient` capture already holds its receipts
    (ADR-029); they are kept, under the side they belong to. Whatever is
    redacted here, from raw text, is counted here.
    """
    redactions: list[str] = []
    receipts: Receipts = {}
    pieces = []
    sides = (("control", control_request, control_response), ("test", test_request, test_response))
    for side, raw_req, raw_resp in sides:
        request, request_hits = _capture_request(raw_req, cap)
        response, response_hits = _capture_response(raw_resp, cap)
        carried = "redaction_receipts" in raw_resp
        for part, hits in (("request", request_hits), ("response", response_hits)):
            for field, counts in hits.items():
                redactions.extend(counts)
                if not (carried and part == "response"):
                    add_receipts(receipts, counts, f"{side}.{part}.{field}")
        if carried:
            # The capture's receipts were counted on the original text, live or
            # recorded, so they are authoritative for the response: counting the
            # text again here would double them live and find nothing on replay.
            for (kind, where), count in receipts_from(
                raw_resp["redaction_receipts"], prefix=side
            ).items():
                receipts[(kind, where)] = receipts.get((kind, where), 0) + count
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
        redaction_receipts=[RedactionReceipt(**r) for r in receipt_list(receipts)],
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
    analysis: dict[str, Any] | None = None,
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
        analysis=analysis,
        captured_at=datetime.now(UTC),
    )


def tls_evidence(
    *,
    label: str,
    observation: Any,
    compared_with: Any | None = None,
    control_rationale: str | None = None,
) -> TlsHandshakeEvidence:
    """Pair a TLS observation with its control.

    By default the control is the verifying client's verdict on the same
    server, which is what `core/tls.py` collects alongside every observation.
    Pass `compared_with` to use a second observation instead - protocol
    enumeration needs observation-vs-observation, because "this server still
    speaks TLS 1.0" is only meaningful beside "and it speaks TLS 1.3 too".
    """
    test = observation.to_dict()

    if compared_with is not None:
        control: dict[str, Any] | None = compared_with.to_dict()
        rationale = control_rationale or (
            "the same server negotiating a current protocol, for comparison"
        )
    elif observation.trusted is not None:
        control = {
            "trusted": observation.trusted,
            "verify_code": observation.verify_code,
            "verify_message": observation.verify_message,
        }
        rationale = control_rationale or (
            "the verdict of a strictly-configured client against the same server; the "
            "observation was taken permissively so the handshake could complete at all"
        )
    else:
        control = None
        rationale = control_rationale or ""

    if not rationale.strip():
        raise ValueError(
            "tls evidence needs a control_rationale explaining what the control is, "
            "or why none is possible"
        )

    return TlsHandshakeEvidence(
        kind="tls_handshake",
        label=label,
        test=test,
        control=control,
        control_rationale=rationale,
        observed_at=observation.observed_at,
        captured_at=datetime.now(UTC),
    )
