"""Render boundaries for host findings (spec 13.3, F1c).

A snapshot comes from a machine that may be compromised, so every byte of it is hostile
until it is encoded for the place it is going. Encoding is per boundary, because each
boundary has a different escape:

- JSON: serialised, never concatenated; `<`, `>` and `&` are also escaped so the text is
  inert even if someone later inlines it in a page.
- HTML: every value is escaped as element text and none is ever an attribute, URL, style or
  markup; a Content-Security-Policy that allows nothing is the second line.
- PDF: every string operand is escaped, and non-ASCII is written as visible text, so a value
  cannot close its string and become an operator.
- Terminal: control characters are made visible, because a terminal is a renderer too.

The rule common to all four: a value is shown as TEXT, present and legible. Dropping it would
make the artefact disagree with what we claim about it (R1), so nothing here removes a
value; it only changes how a control character is written. Long lines are folded, not cut.

This module opens nothing and imports nothing that could (spec 13.2).
"""

from __future__ import annotations

import html
import json
import unicodedata

from core.models import ScanResult

TERMINAL_WIDTH = 100
"""Columns a terminal line is folded to. A 50 KB single-line value is a layout attack on the
reader's terminal, not an injection; folding keeps all of it and bounds the line."""

PDF_WIDTH = 90
PDF_LINES_PER_PAGE = 62

_KEEP = frozenset("\n\t")


def visible(text: str, *, keep: frozenset[str] = _KEEP) -> str:
    """`text` with control and format characters written out as visible escapes.

    Covers C0 and C1 controls (ESC, BEL, NUL, the 8-bit CSI), DEL, the bidirectional
    overrides used for "Trojan Source" and the other format and line-separator characters.
    Ordinary text, including non-ASCII letters, is untouched.
    """
    out: list[str] = []
    for ch in text:
        if ch in keep:
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat in {"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"}:
            code = ord(ch)
            if code < 0x100:
                out.append(f"\\x{code:02x}")
            elif code < 0x10000:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _fold(line: str, width: int) -> list[str]:
    if len(line) <= width:
        return [line]
    return [line[i : i + width] for i in range(0, len(line), width)]


def _plain(result: ScanResult) -> list[tuple[int, str]]:
    """(indent, text) lines of the whole result, every value already `visible`."""
    data = result.model_dump(mode="json")
    rows: list[tuple[int, str]] = [
        (
            0,
            visible(
                f"{data['scanner']} {data['scanner_version']} on {data['target']['value']}"
                f" ({data['outcome']})"
            ),
        )
    ]
    for error in data["errors"]:
        rows.append((0, visible(f"error [{error['stage']}]: {error['message']}")))
    for f in data["findings"]:
        rows.append((0, ""))
        rows.append((0, visible(f"[{f['severity']}] {f['state']} {f['check_id']}")))
        for key in ("title", "description", "impact", "remediation"):
            parts = str(f[key]).split("\n")
            rows.append((2, visible(f"{key}: {parts[0]}")))
            rows.extend((4, visible(part)) for part in parts[1:])
        for e in f["evidence"]:
            rows.append((2, visible(f"evidence ({e['kind']}): {e['label']}")))
            rows.append((4, visible(f"control: {e['control_rationale']}")))
            d = e["data"]
            if "receipt_ref" in d:
                ref = d["receipt_ref"]
                index = ref.get("command_index", ref.get("file_index"))
                rows.append((4, visible(f"receipt: {ref['reason_id']} #{index}")))
            if "argv" in d:
                rows.append((4, visible("argv: " + " ".join(d["argv"]))))
            if "output" in d:
                rows.append((4, "output:"))
                for part in str(d["output"]).split("\n"):
                    rows.append((6, visible(part)))
    return rows


def to_terminal(result: ScanResult) -> str:
    lines: list[str] = []
    for indent, text in _plain(result):
        for piece in _fold(text, TERMINAL_WIDTH - indent):
            lines.append(" " * indent + piece)
    return "\n".join(lines) + "\n"


def to_json(result: ScanResult) -> str:
    text = json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


_HTML_HEAD = (
    '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
    '<meta http-equiv="Content-Security-Policy" '
    "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
    "<title>Host findings</title>"
    "<style>pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all;"
    "font-family:monospace}</style></head><body>\n"
)


def to_html(result: ScanResult) -> str:
    body = "\n".join(
        " " * indent + html.escape(text, quote=True) for indent, text in _plain(result)
    )
    return f"{_HTML_HEAD}<pre>{body}</pre>\n</body></html>\n"


def _pdf_string(text: str) -> str:
    ascii_text = text.encode("ascii", "backslashreplace").decode("ascii")
    return ascii_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def to_pdf(result: ScanResult) -> bytes:
    """A minimal text PDF: Courier, one string operand per line, ASCII only."""
    lines: list[str] = []
    for indent, text in _plain(result):
        for piece in _fold(text, PDF_WIDTH - indent):
            lines.append(" " * indent + piece)
    pages = [
        lines[i : i + PDF_LINES_PER_PAGE] for i in range(0, max(len(lines), 1), PDF_LINES_PER_PAGE)
    ]
    objects: list[bytes] = []

    def add(body: str) -> int:
        objects.append(body.encode("ascii"))
        return len(objects)

    add("<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{4 + 2 * i + 1} 0 R" for i in range(len(pages)))
    add(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    for page in pages:
        ops = ["BT", "/F1 8 Tf", "10 TL", "36 800 Td"]
        ops += [f"({_pdf_string(line)}) Tj T*" for line in page]
        ops.append("ET")
        stream = "\n".join(ops)
        content = add(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
        add(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content} 0 R >>"
        )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode("ascii")
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)
