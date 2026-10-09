"""The one redactor (ADR-028). Secrets out, public key material kept.

Hard constraint 5: never store customer secrets, and redact at capture time,
not at display time. Every place core stores text calls `redact_text`, and
truncation happens only through `cap_text`, which redacts first. Scanners do
not redact; checks read raw data, and only what is *kept* is redacted.

What is removed:

- the token patterns in `SECRET_PATTERNS`;
- **whole PEM private-key blocks**, for any label containing `PRIVATE KEY`
  (including PGP's `PRIVATE KEY BLOCK`), whatever separates their lines (newline,
  CRLF, CR, escaped `\\n`/`\\r\\n`, `<br>`, `&#10;`/`&#xa;`/`&#13;`/`&#xd;`, with
  `/` possibly JSON-escaped). A block with no END line is cut to the end of the
  text, because a key has no safe partial boundary;
- with `heuristics=True` (HTTP bodies, header values, free text): an END line
  whose BEGIN was lost takes the key lines above it, and a run of two or more
  bare 40-100-column base64 lines is cut. These are the truncation-gap cases
  from Tool 4a's leak reviews.

What is kept (the carve-out): public key material. `CERTIFICATE`, `PUBLIC KEY`
and every other non-private PEM label survive whole, and the bare-base64 rule
never touches a run inside or beside one. DNS records and certificate strings
are redacted with `heuristics=False`: token patterns and private-key blocks
only. A DKIM `p=` value is a public key that `dkim-weak-key` measures.

Running it twice gives the same result as once. A whole block becomes
`[redacted:private_key]`, which nothing reads as a block start. Core before
ADR-028 left `[redacted]:private_key` in place of a BEGIN line and kept the
body; with `legacy=True` (replaying a fixture) that marker starts a cut too.
The logic is the scanner-side redactor `web` proved against a 153-case attack
harness in Tool 4a, moved here so that every scanner gets it.
"""

from __future__ import annotations

import bisect
import re
from typing import Any

REDACTED = "[redacted]"
BLOCK_MARKER = "[redacted:private_key]"
LEGACY_KEY_MARKER = f"{REDACTED}:private_key"

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)

# A PEM armour line, as pages actually carry it: 4 or 5 dashes, any case, spaces
# (or URL-encoded spaces) around and inside the label, `PRIVATE-KEY`, PGP's
# `PRIVATE KEY BLOCK`, SSH2's `ENCRYPTED PRIVATE KEY` (review of D21, 8).
_SP = r"(?:[ \t]|%20|\+)"
_DASH = r"-{4,5}"
_PRIVATE_LABEL = rf"(?:[A-Za-z0-9_]|{_SP})*?PRIVATE(?:{_SP}|[-_])?KEY(?:{_SP}+BLOCK)?"


def _armour(word: str) -> str:
    return rf"{_DASH}{_SP}*{word}{_SP}+{_PRIVATE_LABEL}{_SP}*{_DASH}"


_BEGIN = re.compile(_armour("BEGIN"), re.IGNORECASE)
_BEGIN_OR_LEGACY = re.compile(_armour("BEGIN") + "|" + re.escape(LEGACY_KEY_MARKER), re.IGNORECASE)
_END = re.compile(_armour("END"), re.IGNORECASE)
_PUBLIC_LABEL = r"((?:(?!PRIVATE)[A-Za-z0-9 ])+?)"
_PUBLIC_BEGIN = re.compile(rf"{_DASH} ?BEGIN {_PUBLIC_LABEL} ?{_DASH}", re.IGNORECASE)
_PUBLIC_END = re.compile(rf"{_DASH} ?END {_PUBLIC_LABEL} ?{_DASH}", re.IGNORECASE)

# One line break of a key, as a page may carry it: real newlines; escaped once or
# twice in a JSON/JS string; JSON unicode; URL-encoded; an HTML <br>; a newline
# character reference, zero-padded or named (review of D21, 7).
_SEP_ATOM = (
    r"(?:\r?\n|\r|\\\\r\\\\n|\\\\n|\\r\\n|\\n|\\r|\\u000[aAdD]|%0[aAdD]"
    r"|(?i:<br\s*/?>)|&#0*1[03];|(?i:&#x0*[ad];)|&NewLine;)"
)
_SEP = rf"{_SEP_ATOM}(?:[ \t]*{_SEP_ATOM})*"
_B64CH = r"(?:[A-Za-z0-9+=]|\\?/)"
_LINE_END = rf"(?={_SEP_ATOM}|[\"'<`]|\Z)"
_LINE_START = (
    r"(?:(?<=\n)|(?<=\r)|(?<=\\n)|(?<=\\r)|(?<=\\u000[aAdD])|(?<=%0[aAdD])"
    r"|(?<=[>;\"'`])|\A)"
)


def _b64_line(lookahead: str) -> str:
    return rf"[ \t]*(?={lookahead})(?:{_B64CH})+[ \t]*{_LINE_END}"


_B64_FULL = _b64_line(rf"(?:{_B64CH}){{40,100}}(?!{_B64CH})")
_B64_ANY = _b64_line(rf"(?:{_B64CH}){{1,100}}(?!{_B64CH})")
_B64_LAST = _b64_line(rf"(?:{_B64CH}){{16,100}}(?!{_B64CH})|(?:{_B64CH}){{0,99}}=")
_AFTER_TRUNCATION = r"(?<=bytes truncated\] \.\.\.\n)"
_BARE_KEY_RUN = re.compile(
    rf"(?:{_AFTER_TRUNCATION}{_B64_ANY}(?:{_SEP}{_B64_FULL})+"
    rf"|{_LINE_START}{_B64_FULL}(?:{_SEP}{_B64_FULL})+)"
    rf"(?:{_SEP}{_B64_LAST})?"
)
_BARE_SPACED_RUN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{40,100}[ \t]+){2,}[A-Za-z0-9+/]{16,100}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)
"""Key lines joined by spaces or tabs (the `.env` shape), three or more, no anchor."""
_SEP_TAIL = re.compile(rf"(?:{_SEP_ATOM})\Z")
_PUBLIC_BODY = re.compile(rf"(?:{_SEP_ATOM}|[ \t]|[A-Za-z0-9+/=]|\\/)*")
_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_LONG_B64 = re.compile(r"[A-Za-z0-9+=/]{40}")
"""A bare key run needs 40 base64 characters in a row. Ordinary pages have none,
so this C-speed check skips the expensive run search for almost every page."""
_BOUNDARY = frozenset("\n\r>;\"'`")
_LEADING_SEPS = re.compile(rf"(?:[ \t]|{_SEP_ATOM})*")
_FIRST_SEP = re.compile(_SEP_ATOM)
_TRUNCATION_MARK = re.compile(r"\n\.\.\. \[\d+ bytes truncated\] \.\.\.\n")
_ANY_MARKER = re.compile(r"\[redacted(?::[a-z_]+\]|\](?::[a-z_]+)?)")

Counts = dict[str, int]

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
"""Headers whose whole value is a credential, so it is replaced without matching."""


def redact_header_map(headers: dict[str, str], counts: Counts | None = None) -> dict[str, str]:
    """Redact headers by name *and* by value (ADR-028, ledger D21)."""
    counts = counts if counts is not None else {}
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        clean_key, hit = redact_text(key)
        _merge(counts, hit)
        clean_key = clean_key or key
        if key.lower() in SENSITIVE_HEADERS:
            cleaned[clean_key] = REDACTED if value != REDACTED else value
            if value != REDACTED:
                counts[key.lower()] = counts.get(key.lower(), 0) + 1
        else:
            clean_value, hit = redact_text(value)
            _merge(counts, hit)
            cleaned[clean_key] = clean_value if clean_value is not None else value
    return cleaned


PUBLIC_DATA_KINDS = frozenset({"dns_answer", "tls_handshake"})
"""Evidence made of public records and certificates: token patterns and private-key
blocks only, never the bare-base64 heuristic (ADR-028 clause 2). Every other kind,
including a file excerpt or an OOB request, gets the full redactor."""


def _heuristics_for(evidence: dict[str, Any]) -> bool:
    return evidence.get("kind") not in PUBLIC_DATA_KINDS


Receipts = dict[tuple[str, str], int]
"""(kind, where) -> how many were removed there (ADR-029)."""


def add_receipts(receipts: Receipts, counts: Counts, where: str) -> None:
    for kind, count in counts.items():
        if count:
            receipts[(kind, where)] = receipts.get((kind, where), 0) + count


def receipt_list(receipts: Receipts) -> list[dict[str, Any]]:
    """The stored form: `[{kind, count, where}]`, in a stable order."""
    return [
        {"kind": kind, "count": count, "where": where}
        for (kind, where), count in sorted(receipts.items(), key=lambda kv: (kv[0][1], kv[0][0]))
    ]


def receipts_from(items: Any, prefix: str = "") -> Receipts:
    """Read stored receipts back, optionally under a `where` prefix."""
    out: Receipts = {}
    for item in items or []:
        if hasattr(item, "model_dump"):
            item = item.model_dump()
        if isinstance(item, dict) and item.get("count"):
            where = f"{prefix}.{item['where']}" if prefix else str(item["where"])
            out[(str(item["kind"]), where)] = out.get((str(item["kind"]), where), 0) + int(
                item["count"]
            )
    return out


def redact_evidence(data: dict[str, Any]) -> dict[str, Any]:
    """Redact a serialised evidence item, whichever way it was built.

    HTTP exchanges and every other kind get the full redactor. DNS and TLS
    evidence, which is public records and certificate data, gets token patterns
    and private-key blocks only, so public key material survives (clause 2).
    The kinds removed are added to `redactions`, and a receipt per kind and part
    to `redaction_receipts` (ADR-029). Receipts already on the item are kept:
    re-redacting stored text finds nothing new, so nothing is counted twice.
    """
    counts: Counts = {}
    receipts = receipts_from(data.get("redaction_receipts"))
    out = dict(data)
    for side in ("control", "test"):
        exchange = out.get(side)
        if exchange is not None and hasattr(exchange, "model_dump"):
            exchange = exchange.model_dump()
        if out.get("kind") == "http_pair" and isinstance(exchange, dict):
            exchange = dict(exchange)
            for part in ("request", "response"):
                piece = exchange.get(part)
                if not isinstance(piece, dict):
                    continue
                piece = dict(piece)
                if isinstance(piece.get("url"), str):
                    piece["url"], hit = redact_text(piece["url"])
                    _merge(counts, hit)
                    add_receipts(receipts, hit, f"{side}.{part}.url")
                if isinstance(piece.get("headers"), dict):
                    hit = {}
                    piece["headers"] = redact_header_map(piece["headers"], hit)
                    _merge(counts, hit)
                    add_receipts(receipts, hit, f"{side}.{part}.headers")
                if isinstance(piece.get("body"), str):
                    piece["body"], hit = redact_text(piece["body"])
                    _merge(counts, hit)
                    add_receipts(receipts, hit, f"{side}.{part}.body")
                exchange[part] = piece
            out[side] = exchange
        elif isinstance(exchange, dict):
            cleaned = {}
            for part, value in exchange.items():
                hit = {}
                # keys as well as values: a key can hold a secret too (review of
                # ADR-029; main redacted the whole side, keys included)
                clean_part = redact_data(part, heuristics=_heuristics_for(out), counts=hit)
                cleaned[clean_part] = redact_data(
                    value, heuristics=_heuristics_for(out), counts=hit
                )
                _merge(counts, hit)
                add_receipts(receipts, hit, f"{side}.{_field_name(clean_part)}")
            out[side] = cleaned
        elif exchange is not None:
            hit = {}
            out[side] = redact_data(exchange, heuristics=_heuristics_for(out), counts=hit)
            _merge(counts, hit)
            add_receipts(receipts, hit, side)
    for key, value in list(out.items()):
        if key in ("control", "test", "kind", "captured_at", "redactions", "redaction_receipts"):
            continue
        hit = {}
        out[key] = redact_data(value, heuristics=_heuristics_for(out), counts=hit)
        _merge(counts, hit)
        add_receipts(receipts, hit, _field_name(key))
    if counts:
        out["redactions"] = sorted(set(out.get("redactions") or []) | set(counts))
    if receipts or "redaction_receipts" in out:
        out["redaction_receipts"] = receipt_list(receipts)
    return out


def _field_name(key: Any) -> str:
    """A `where` segment: a schema field name, never data (ADR-029 clause 2)."""
    name = str(key)
    return name if re.fullmatch(r"[a-z_]+", name) else "data"


def redact_text(
    text: str | None, *, heuristics: bool = True, legacy: bool = False
) -> tuple[str | None, Counts]:
    """Remove secrets from `text`. Returns the text and how many of each kind went.

    `heuristics=False` for public data (DNS records, certificate strings).
    `legacy=True` only when re-redacting a fixture recorded before ADR-028.
    """
    if not text:
        return text, {}
    counts: Counts = {}
    text = _redact_private_keys(text, counts, heuristics=heuristics, legacy=legacy)
    for name, pattern in SECRET_PATTERNS:
        text, n = pattern.subn(f"{REDACTED}:{name}", text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts


def redact_data(value: Any, *, heuristics: bool = False, counts: Counts | None = None) -> Any:
    """Redact every string inside a JSON-like value (dict keys included)."""
    counts = counts if counts is not None else {}
    if hasattr(value, "model_dump"):  # a nested model, not yet serialised
        value = value.model_dump()
    if isinstance(value, str):
        out, hit = redact_text(value, heuristics=heuristics)
        _merge(counts, hit)
        return out
    if isinstance(value, dict):
        return {
            redact_data(k, heuristics=heuristics, counts=counts): redact_data(
                v, heuristics=heuristics, counts=counts
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_data(v, heuristics=heuristics, counts=counts) for v in value]
    return value


def cap_text(text: str | None, cap: int) -> tuple[str | None, bool]:
    """Redact, then cap at `cap` characters keeping the head and the tail.

    The only way core truncates text (ADR-028 clause 4). Cutting first could
    split a secret so its pattern no longer matched and leave its prefix in
    storage. A cut never falls inside a marker, and the result is redacted
    again, because a cut can create a word boundary a pattern needs.
    """
    text, _ = redact_text(text)
    if text is None or len(text) <= cap:
        return text, False
    head_end = _outside_marker(text, cap // 2, prefer_left=True)
    tail_start = _outside_marker(text, len(text) - (cap - cap // 2), prefer_left=False)
    if tail_start < head_end:
        tail_start = head_end
    omitted = tail_start - head_end
    capped = f"{text[:head_end]}\n... [{omitted} bytes truncated] ...\n{text[tail_start:]}"
    return redact_text(capped)[0], True


def cap_prefix(text: str, cap: int, suffix: str = " ... (truncated)") -> str:
    """Redact, then keep at most `cap` characters from the start, `suffix` included.

    For text shown to a reader (a description, an excerpt), where only the
    start is useful. Same rule as `cap_text`: redaction first, a cut never
    falls inside a marker, and the cut text is redacted again. This is web's
    Tool 4a `_capped`, which had to be fixed for cap-before-redact, moved to
    core so no scanner writes its own.
    """
    redacted, _ = redact_text(text)
    text = redacted or ""
    if len(text) <= cap:
        return text
    room = cap - len(suffix)
    limit = room
    while limit > 0:
        limit = _outside_marker(text, limit, prefer_left=True)
        piece = redact_text(text[:limit].rstrip())[0] or ""
        if len(piece) <= room:
            return piece + suffix
        limit -= len(piece) - room
    return suffix.strip()[:cap]


def _outside_marker(text: str, at: int, *, prefer_left: bool) -> int:
    for marker in _ANY_MARKER.finditer(text, max(0, at - 64), min(len(text), at + 64)):
        if marker.start() < at < marker.end():
            return marker.start() if prefer_left else marker.end()
    return at


def _merge(into: Counts, more: Counts) -> None:
    for kind, n in more.items():
        into[kind] = into.get(kind, 0) + n


# --- private-key blocks -------------------------------------------------------


def _redact_private_keys(text: str, counts: Counts, *, heuristics: bool, legacy: bool) -> str:
    anchor = _BEGIN_OR_LEGACY if legacy else _BEGIN
    ends = [m.span() for m in _END.finditer(text)]
    if ends or anchor.search(text) is not None:
        text = _cut_key_blocks(text, ends, anchor, counts)
    if not heuristics:
        return text
    if _END.search(text):
        text = _strip_orphan_key_tails(text, anchor, counts)
    return _strip_bare_runs(text, counts)


def _cut_key_blocks(
    text: str, ends: list[tuple[int, int]], anchor: re.Pattern[str], counts: Counts
) -> str:
    """Each block runs from its anchor to the first END line after it; with none,
    to the end of the text. One pass, so a page of unterminated anchors stays linear."""
    starts = [start for start, _ in ends]
    out: list[str] = []
    pos = 0
    for found in anchor.finditer(text):
        if found.start() < pos:
            continue  # inside a block already cut
        out.append(text[pos : found.start()])
        out.append(BLOCK_MARKER)
        counts["private_key"] = counts.get("private_key", 0) + 1
        i = bisect.bisect_left(starts, found.end())
        if i >= len(ends):
            return "".join(out)  # unterminated: everything after the anchor goes
        pos = ends[i][1]
    out.append(text[pos:])
    return "".join(out)


def _strip_orphan_key_tails(text: str, anchor: re.Pattern[str], counts: Counts) -> str:
    """An END line no anchor claimed: its BEGIN was lost, typically to a truncation
    gap. If a truncation note precedes it with no anchor between, everything from the
    note to the END goes (the note is kept). Otherwise walk back over the key lines."""
    marks = [m.end() for m in _TRUNCATION_MARK.finditer(text)]
    out: list[str] = []
    pos = 0
    for end in _END.finditer(text):
        i = bisect.bisect_right(marks, end.start()) - 1
        mark = marks[i] if i >= 0 else -1
        if mark >= pos and anchor.search(text, mark, end.start()) is None:
            start = mark
        else:
            start = _key_tail_start(text, pos, end.start())
        out.append(text[pos:start] + BLOCK_MARKER)
        counts["private_key"] = counts.get("private_key", 0) + 1
        pos = end.end()
    out.append(text[pos:])
    return "".join(out)


def _public_spans(text: str) -> list[tuple[int, int]]:
    """Every public PEM block (certificate, public key, ...), BEGIN to its END.

    Linear (review of D21, 3): each label's END lines are found once and matched
    by bisection. A public BEGIN with no END protects only the base64 body that
    follows it, not the rest of the text (review nit).
    """
    ends: dict[str, list[int]] = {}
    for end in _PUBLIC_END.finditer(text):
        ends.setdefault(end.group(1).upper(), []).append(end.start())
    spans: list[tuple[int, int]] = []
    for begin in _PUBLIC_BEGIN.finditer(text):
        starts = ends.get(begin.group(1).upper(), [])
        i = bisect.bisect_left(starts, begin.end())
        if i < len(starts):
            spans.append((begin.start(), starts[i]))
        else:
            body = _PUBLIC_BODY.match(text, begin.end())
            spans.append((begin.start(), body.end() if body else begin.end()))
    spans.sort()
    merged: list[tuple[int, int]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _in_public(spans: list[tuple[int, int]], lo: int, hi: int) -> bool:
    i = bisect.bisect_right(spans, (hi, len("x") << 62)) - 1
    return i >= 0 and spans[i][1] >= lo


def _strip_bare_runs(text: str, counts: Counts) -> str:
    """Two or more whole base64 lines with no anchor: a key body whose BEGIN and END
    both fell into a truncation gap. Never inside or beside public key material.

    Counted as `possible_key_material`, not `private_key`: a heuristic cut is a
    reason to keep text out of storage, never a verdict that a key was exposed
    (review of D21, 1)."""
    if _LONG_B64.search(text) is None and "\\/" not in text:
        return text
    spans = _public_spans(text)

    def cut(run: re.Match[str]) -> str:
        if _in_public(spans, run.start(), run.end()):
            return run.group()
        after = _LEADING_SEPS.match(text, run.end())
        if after is not None and _PUBLIC_END.match(text, after.end()):
            return run.group()  # the tail of a certificate whose BEGIN was cut away
        counts["possible_key_material"] = counts.get("possible_key_material", 0) + 1
        return BLOCK_MARKER

    text = _BARE_KEY_RUN.sub(cut, text)
    spans = _public_spans(text)
    return _BARE_SPACED_RUN.sub(cut, text)


def _ends_with_sep(text: str, lo: int, i: int) -> int:
    """Length of the line break ending at text[i], or 0."""
    if i <= lo:
        return 0
    ch = text[i - 1]
    if ch in "\n\r":
        return 1
    tail = _SEP_TAIL.search(text, max(lo, i - 16), i)
    return i - tail.start() if tail is not None else 0


def _key_tail_start(text: str, lo: int, hi: int) -> int:
    """Where the key lines that end at text[hi] (an orphan END line) begin. Walks back
    over base64, escaped "/", line breaks and indentation; linear in what it eats.
    Never ends inside a line of ordinary text: a partial line is given back."""
    i, after_sep = hi, True
    while i > lo:
        if n := _ends_with_sep(text, lo, i):
            i, after_sep = i - n, True
            continue
        ch = text[i - 1]
        if ch == "/" and i - 2 >= lo and text[i - 2] == "\\":
            i, after_sep = i - 2, False
        elif ch in _KEY_CHARS:
            i, after_sep = i - 1, False
        elif ch in " \t":
            j = i
            while j > lo and text[j - 1] in " \t":
                j -= 1
            if not (after_sep or j == lo or _ends_with_sep(text, lo, j)):
                break  # spaces between words: ordinary text
            i = j
        else:
            break
    start = _LEADING_SEPS.match(text, i, hi)
    i = start.end() if start else i
    if i > lo and text[i - 1] not in _BOUNDARY and not _ends_with_sep(text, lo, i):
        sep = _FIRST_SEP.search(text, i, hi)
        if sep is not None:
            rest = _LEADING_SEPS.match(text, sep.end(), hi)
            i = rest.end() if rest else sep.end()
    return i
