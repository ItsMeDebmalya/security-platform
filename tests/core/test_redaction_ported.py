"""web's scanner-side redactor unit tests, ported to core (D21 step d).

These tested `scanners.web.scanner._strip_private_keys`, the Tool 4a workaround
that ADR-028 moved into `core/redaction.py`. Same inputs, same safety
properties; two things changed on purpose:

- the marker for a removed block is `[redacted:private_key]`;
- running redaction twice is now the same as once. web's version was "not
  idempotent by design", which is why web needed its `pre_redacted` path.

Inputs that start with core's *old* marker, `[redacted]:private_key`, are
fixtures recorded before ADR-028, so they are redacted with `legacy=True`, as
`ReplayHttpBackend` does.
"""

from __future__ import annotations

import time

from core.redaction import BLOCK_MARKER as M
from core.redaction import redact_text
from tests.core.test_redaction import key_lines

BEGIN, END = "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"


def r(text: str, **kwargs) -> str:
    return redact_text(text, **kwargs)[0] or ""


def test_bare_base64_runs_are_stripped_but_single_lines_are_not():
    lines = key_lines(4)
    assert r(f"a\n{lines[0]}\n{lines[1]}\nb") == f"a\n{M}\nb"
    assert r(f"a\r\n  {lines[0]}  \r\n{lines[1]}\r\nb") == f"a\r\n{M}\r\nb"
    escaped = f'{{"k": "{lines[0]}\\n{lines[1]}\\n{lines[2]}", "n": 1}}'
    assert r(escaped) == f'{{"k": "{M}", "n": 1}}'
    assert r(f"{lines[0]}\n{lines[1][:60]}==\n") == f"{M}\n"
    data_uri = (
        '<img src="data:image/png;base64,' + "".join(key_lines(40)) + '">\n'
        "<p>An ordinary paragraph of text, nothing secret here.</p>\n"
    )
    assert r(data_uri) == data_uri
    single = f"<p>hash</p>\n{lines[0]}\n<p>more prose</p>"
    assert r(single) == single
    short_run = f"{lines[0][:30]}\n{lines[1][:30]}\n"
    assert r(short_run) == short_run


def test_bare_run_stripping_is_linear():
    line = key_lines(1)[0]
    for text in (
        (line + " x\n") * 4000,
        ("A" * 59 + "\n") * 4000,
        "A" * 262_144,
        ("\n" + "A" * 77) * 3000,
    ):
        started = time.monotonic()
        r(text)
        assert time.monotonic() - started < 1.0


def test_unterminated_blocks_are_cut_to_the_end_and_text_after_end_is_kept():
    legacy = "[redacted]:private_key"
    # core's old marker on its own is inert in fresh text, and an anchor on replay
    assert r(legacy) == legacy
    assert r(legacy, legacy=True) == M
    replayed = f"{legacy}\nMIIabc\nMIIdef\n-----END PRIVATE KEY-----\nThe end."
    assert r(replayed, legacy=True) == f"{M}\nThe end."
    bare = f"a {legacy}\nMIIabc\nMIIdef\n</pre>\n<p>Contact us at the desk.</p>"
    assert r(bare, legacy=True) == f"a {M}"
    assert r("a -----BEGIN PRIVATE KEY-----<br>\nMIIabc<br>\nrest") == f"a {M}"
    escaped = (
        '{"k": "-----BEGIN PRIVATE KEY-----\\nMIIabc\\nMIIdef\\n-----END PRIVATE KEY-----\\n"}'
    )
    assert r(escaped) == f'{{"k": "{M}\\n"}}'
    assert r(f'{{"k": "{legacy}\\nMIIabc\\nMIIdef", "n": 1}}', legacy=True) == f'{{"k": "{M}'
    orphan = (
        "intro line here\n... [9 bytes truncated] ...\nIIabc\nMIIdef\n"
        "-----END PRIVATE KEY-----\nok, done."
    )
    assert r(orphan) == f"intro line here\n... [9 bytes truncated] ...\n{M}\nok, done."
    for sep in ("<br>\n", "<BR />", "&#10;", "&#xD;&#xA;", "\\n"):
        text = f"<p>see below</p>{sep}ab\\/cd{sep}MIIdef{sep}{END}{sep}kept"
        assert r(text) == f"<p>see below</p>{sep}{M}{sep}kept", sep
    assert r("some prose words\nMIIabc\n-----END PRIVATE KEY-----\nkept") == (
        f"some prose words\n{M}\nkept"
    )
    # ADR-028 clause 7: twice is the same as once (web's version was not)
    once = r(replayed, legacy=True)
    assert r(once) == once and r(once, legacy=True) == once


def test_unterminated_private_key_is_stripped_to_the_end():
    text, counts = redact_text("a -----BEGIN PRIVATE KEY-----\nMIIabc\nMIIdef")
    assert text == f"a {M}" and counts == {"private_key": 1}
    two = (
        "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\nkeep\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n-----END OPENSSH PRIVATE KEY-----"
    )
    assert r(two) == f"{M}\nkeep\n{M}"


def test_truncation_marker_cut_needs_no_anchor_between():
    gap = "\n... [123 bytes truncated] ...\n"
    text = "head" + gap + "odd<x>MIIabc odd<x>MIIdef " + END + " after"
    assert r(text) == "head" + gap + f"{M} after"
    # a complete block after the note is cut on its own; the prose between stays
    text = "head" + gap + "prose stays " + BEGIN + "\nMIIabc\n" + END + " after"
    assert r(text) == "head" + gap + f"prose stays {M} after"
