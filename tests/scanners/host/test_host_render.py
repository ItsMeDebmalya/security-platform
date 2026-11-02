"""F1c: output encoding at every render boundary, proved by planted payloads (spec 13.3).

The assertion is POSITIVE. The payload must be present and inert in JSON, HTML, PDF and
terminal output; a test that only checked absence would pass when the value was silently
dropped, and a dropped value is an R1 failure.
"""

from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime

import pytest
from host_snapshots import rehash, to_bytes

from core.models import Asset, CheckRun, Finding, ScanResult, Telemetry
from scanners.host import reader, render

SCRIPT = "<script>alert(1)</script>"
ANSI = "\x1b[2J\x1b[1;1H\x1b[31mred\x1b[0m\x1b]0;pwned\x07"
BIDI = "‮evil‬"
LONG = "L" * 50_000
PAYLOAD = f"{SCRIPT}|{ANSI}|{BIDI}"


def _result_with(output: str, *, description: str = "d") -> ScanResult:
    """A scan result whose one finding carries `output` in its evidence, built the way a
    check builds it (Finding.create), so the renderers see a real model."""
    now = datetime(2026, 10, 29, 9, 50, 4, tzinfo=UTC)
    target = Asset(type="host", value="lab-vm-1")
    finding = Finding.create(
        org_id="org_internal",
        scanner="host",
        scanner_version="0.1.0",
        vantage="agent",
        engagement="defensive",
        check_id="host-ssh-root-login",
        title="Root login is permitted",
        target=target,
        location="$",
        severity="high",
        confidence=0.9,
        detection_methods=[
            {
                "method": "m",
                "likelihood_ratio": 10.0,
                "independence_class": "c",
                "prior": 0.5,
                "prior_justification": "j",
            }
        ],
        validation={"attempted": False, "outcome": "not_applicable"},
        evidence=[
            {
                "kind": "command_output",
                "label": "sections.ssh",
                "captured_at": now,
                "control_rationale": "expected prohibit-password",
                "data": {
                    "argv": ["/usr/sbin/sshd", "-T"],
                    "exit_status": 0,
                    "output": output,
                    "output_selection": {
                        "method": "whole",
                        "detail": "x",
                        "captured_bytes": len(output),
                        "truncated": False,
                    },
                    "receipt_ref": {"reason_id": "ssh.effective", "command_index": 0},
                    "collected_at": now,
                    "host_ref": "sha256:474cbba19098a942",
                },
            }
        ],
        description=description,
        impact="i",
        remediation="r",
        first_seen=now,
        first_seen_scan_id="s",
        last_seen=now,
        last_seen_scan_id="s",
    )
    return ScanResult(
        scanner="host",
        scanner_version="0.1.0",
        target=target,
        mode="light",
        findings=[finding],
        telemetry=Telemetry(checks_run=[CheckRun(check_id=finding.check_id, outcome="reported")]),
    )


@pytest.fixture
def planted_result() -> ScanResult:
    return _result_with(f"{PAYLOAD}\n{LONG}")


def _evidence_text(result) -> str:
    return "\n".join(
        e.data.output for f in result.findings for e in f.evidence if hasattr(e.data, "output")
    )


def test_the_payload_reaches_the_finding_at_all(planted_result):
    # guards the whole file: if the payload never got in, every test below is vacuous
    text = _evidence_text(planted_result)
    assert SCRIPT in text and "\x1b[2J" in text and LONG in text


def test_visible_makes_controls_text_and_leaves_ordinary_text():
    assert render.visible("plain ünïcode\nline2\ttab") == "plain ünïcode\nline2\ttab"
    assert render.visible("\x1b[2J") == "\\x1b[2J"
    assert render.visible("a\x00b") == "a\\x00b"
    assert render.visible("\x9b31m") == "\\x9b31m"  # a C1 CSI is an escape too
    assert "‮" not in render.visible("‮abc")  # bidi override (Trojan Source)
    assert render.visible("‮abc") == "\\u202eabc"


def test_json_is_serialised_not_concatenated_and_roundtrips(planted_result):
    out = render.to_json(planted_result)
    data = json.loads(out)
    text = "\n".join(
        e["data"]["output"]
        for f in data["findings"]
        for e in f["evidence"]
        if "output" in e["data"]
    )
    assert SCRIPT in text and ANSI in text and BIDI in text and LONG in text  # present, exact
    assert "\x1b" not in out and "<script>" not in out and "‮" not in out  # inert on the wire


def test_html_escapes_in_context_and_shows_the_payload_as_text(planted_result):
    out = render.to_html(planted_result)
    assert "<script" not in out.lower().replace("&lt;script", "")  # no live script element
    assert not re.search(r"<script", out, re.I)
    assert "\x1b" not in out and "‮" not in out
    shown = html.unescape(re.sub(r"<[^>]+>", "", out))
    assert render.visible(SCRIPT) in shown
    assert "\\x1b[2J\\x1b[1;1H" in shown  # the ANSI run, visible
    assert LONG in shown.replace("\n", "")  # present; layout is CSS's job, not truncation
    assert "overflow-wrap" in out  # the long-line layout defence is in the document
    assert "default-src 'none'" in out  # nothing can load or run even if escaping failed


def test_html_never_puts_a_value_in_an_attribute_or_url(planted_result):
    out = render.to_html(planted_result)
    attrs = re.findall(r"<[a-z]+\s([^>]*)>", out)
    for a in attrs:
        assert "alert" not in a and "script" not in a.lower()
    assert "href=" not in out and "src=" not in out


def _pdf_text(pdf: bytes) -> str:
    """Pull the text operands back out the way a reader would: Tj strings, unescaped."""
    body = pdf.decode("latin-1")
    out = []
    for m in re.finditer(r"\((?:\\.|[^\\()])*\)\s*Tj", body):
        raw = m.group(0)[1 : m.group(0).rindex(")")]
        out.append(re.sub(r"\\(.)", r"\1", raw))
    return "\n".join(out)


def test_pdf_strings_are_escaped_and_the_payload_is_present_as_text(planted_result):
    pdf = render.to_pdf(planted_result)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"\x1b" not in pdf
    pdf.decode("ascii")  # pure ASCII: nothing for an encoding trick to hide in
    text = _pdf_text(pdf)
    flat = text.replace("\n", "")
    assert render.visible(SCRIPT) in flat or SCRIPT in flat  # as text, inside a string
    assert "\\x1b[2J" in flat.replace("\\\\", "\\")
    assert LONG in re.sub(r"\s", "", flat)  # a 50 KB line is folded across lines, not dropped


def test_pdf_unbalanced_parentheses_cannot_break_out_of_the_string():
    planted = ") Tj /Evil (x\\) ("
    pdf = render.to_pdf(_result_with(planted))
    # the planted text is inside a string operand, and outside every string there is no /Evil
    assert planted in _pdf_text(pdf).replace("\n", "")
    assert b"/Evil" not in re.sub(rb"\((?:\\.|[^\\()])*\)", b"", pdf)


def test_terminal_shows_controls_as_text_and_folds_the_long_line(planted_result):
    out = render.to_terminal(planted_result)
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "\\x1b[2J\\x1b[1;1H" in out and SCRIPT in out
    assert LONG in re.sub(r"\s", "", out)
    assert max(len(line) for line in out.splitlines()) <= render.TERMINAL_WIDTH + 8


def test_a_value_in_an_error_message_goes_through_the_same_boundary(clean_snapshot):
    clean_snapshot["host"]["hostname"] = "\x1b[2J<script>"
    with pytest.raises(reader.SnapshotError) as err:
        reader.parse(to_bytes(rehash(clean_snapshot)))
    assert "\x1b" not in str(err.value) and "<script>" not in str(err.value)
