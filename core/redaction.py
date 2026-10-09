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

_PRIVATE_LABEL = r"[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?"
_BEGIN = re.compile(rf"-----BEGIN {_PRIVATE_LABEL}-----")
_BEGIN_OR_LEGACY = re.compile(rf"-----BEGIN {_PRIVATE_LABEL}-----|{re.escape(LEGACY_KEY_MARKER)}")
_END = re.compile(rf"-----END {_PRIVATE_LABEL}-----")
_PUBLIC_BEGIN = re.compile(r"-----BEGIN ((?:(?!PRIVATE KEY)[A-Z0-9 ])+)-----")
_PUBLIC_END_AHEAD = re.compile(r"-----END (?:(?!PRIVATE KEY)[A-Z0-9 ])+-----")

_SEP_ATOM = r"(?:\r?\n|\r|\\r\\n|\\n|\\r|(?i:<br\s*/?>)|&#1[03];|(?i:&#x[ad];))"
_SEP = rf"{_SEP_ATOM}(?:[ \t]*{_SEP_ATOM})*"
_B64CH = r"(?:[A-Za-z0-9+=]|\\?/)"
_LINE_END = rf"(?={_SEP_ATOM}|[\"'<`]|\Z)"
_LINE_START = r"(?:(?<=\n)|(?<=\r)|(?<=\\n)|(?<=\\r)|(?<=[>;\"'`])|\A)"


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
_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_BR_TAIL = re.compile(r"(?i)<br\s*/?>\Z")
_ENTITY_BREAKS = frozenset({"&#10;", "&#13;", "&#xa;", "&#xd;"})
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


def redact_evidence(data: dict[str, Any]) -> dict[str, Any]:
    """Redact a serialised evidence item, whichever way it was built.

    HTTP exchanges get the full redactor; everything else, including DNS
    records, certificate data and analysis trees, gets token patterns and
    private-key blocks only, so public key material survives (clause 2).
    The kinds removed are added to `redactions`.
    """
    counts: Counts = {}
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
                if isinstance(piece.get("headers"), dict):
                    piece["headers"] = redact_header_map(piece["headers"], counts)
                if isinstance(piece.get("body"), str):
                    piece["body"], hit = redact_text(piece["body"])
                    _merge(counts, hit)
                exchange[part] = piece
            out[side] = exchange
        elif exchange is not None:
            out[side] = redact_data(exchange, counts=counts)
    for key, value in list(out.items()):
        if key in ("control", "test", "kind", "captured_at", "redactions"):
            continue
        out[key] = redact_data(value, heuristics=key == "label", counts=counts)
    if counts:
        out["redactions"] = sorted(set(out.get("redactions") or []) | set(counts))
    return out


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
    """Every public PEM block (certificate, public key, ...), BEGIN to its END."""
    spans = []
    for begin in _PUBLIC_BEGIN.finditer(text):
        end = text.find(f"-----END {begin.group(1)}-----", begin.end())
        spans.append((begin.start(), len(text) if end < 0 else end))
    return spans


_LONG_B64 = re.compile(r"[A-Za-z0-9+=/]{40}")
"""A bare key run needs 40 base64 characters in a row. Ordinary pages have none,
so this C-speed check skips the expensive run search for almost every page."""


def _strip_bare_runs(text: str, counts: Counts) -> str:
    """Two or more whole base64 lines with no anchor: a key body whose BEGIN and END
    both fell into a truncation gap. Never inside or beside public key material."""
    if _LONG_B64.search(text) is None and "\\/" not in text:
        return text
    spans = _public_spans(text)

    def cut(run: re.Match[str]) -> str:
        if any(lo <= run.end() and run.start() <= hi for lo, hi in spans):
            return run.group()
        after = _LEADING_SEPS.match(text, run.end())
        if after is not None and _PUBLIC_END_AHEAD.match(text, after.end()):
            return run.group()  # the tail of a certificate whose BEGIN was cut away
        counts["private_key"] = counts.get("private_key", 0) + 1
        return BLOCK_MARKER

    return _BARE_KEY_RUN.sub(cut, text)


def _ends_with_sep(text: str, lo: int, i: int) -> int:
    """Length of the line break ending at text[i], or 0."""
    if i <= lo:
        return 0
    ch = text[i - 1]
    if ch in "\n\r":
        return 1
    if ch in "nr" and i - 2 >= lo and text[i - 2] == "\\":
        return 2
    if ch == ";" and text[max(lo, i - 5) : i].lower() in _ENTITY_BREAKS:
        return 5
    if ch == ">" and (br := _BR_TAIL.search(text, max(lo, i - 16), i)) is not None:
        return i - br.start()
    return 0


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
