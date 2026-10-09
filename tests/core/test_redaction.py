"""ADR-028: core redacts secrets by value, everywhere text is stored.

Written before the implementation (D21). Every test here must fail on the core
that predates ADR-028: it matched header names only, kept private-key bodies,
and never redacted finding text, errors or logs.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from core.redaction import (
    BLOCK_MARKER,
    LEGACY_KEY_MARKER,
    cap_text,
    redact_text,
)

AWS = "AKIAIOSFODNN7EXAMPLE"  # AWS's own published example key
GHP = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xoxb-123456789012-abcdefABCDEF"
GOOGLE = "AIza" + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v"
BEARER = "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456"
TOKENS = {
    "aws_access_key_id": AWS,
    "github_token": GHP,
    "slack_token": SLACK,
    "google_api_key": GOOGLE,
    "bearer_token": BEARER,
}


def key_lines(n: int = 30, width: int = 64, seed: int = 0) -> list[str]:
    raw = b"".join(
        hashlib.sha256(bytes([seed]) + i.to_bytes(2, "big")).digest() for i in range(n * 2)
    )
    text = base64.b64encode(raw).decode()[: n * width - 20]
    return [text[i : i + width] for i in range(0, len(text), width)]


LINES = key_lines()


def pem(lines: list[str], sep: str = "\n", end: bool = True, label: str = "RSA PRIVATE KEY") -> str:
    out = f"-----BEGIN {label}-----" + sep + sep.join(lines)
    return out + (sep + f"-----END {label}-----" if end else "")


def leaked(stored: str | None, lines: list[str] = LINES) -> list[str]:
    stored = stored or ""
    return [line for line in lines if line in stored or line[-24:] in stored]


# --- token patterns ---------------------------------------------------------


@pytest.mark.parametrize(("kind", "secret"), list(TOKENS.items()))
def test_each_token_pattern_is_redacted_and_counted(kind, secret):
    text, counts = redact_text(f"before {secret} after")

    assert secret not in text
    assert counts == {kind: 1}


def test_counts_are_per_kind_and_per_occurrence():
    _, counts = redact_text(f"{AWS} and {AWS} and {GHP}")

    assert counts == {"aws_access_key_id": 2, "github_token": 1}


def test_text_with_no_secret_is_unchanged():
    text = "Server: nginx/1.25.3 (Ubuntu)"

    assert redact_text(text) == (text, {})


# --- whole private-key blocks -------------------------------------------------

LABELS = [
    "RSA PRIVATE KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
]
SEPARATORS = ["\n", "\r\n", "\r", "\\n", "\\r\\n", "<br>", "<br/>", "<BR />\n", "&#10;", "&#xa;"]


@pytest.mark.parametrize("label", LABELS)
@pytest.mark.parametrize("sep", SEPARATORS)
@pytest.mark.parametrize("end", [True, False], ids=["terminated", "unterminated"])
def test_a_private_key_block_is_removed_whole(label, sep, end):
    text, counts = redact_text("<pre>" + pem(LINES, sep=sep, end=end, label=label) + "</pre>")

    assert leaked(text) == []
    assert "END " + label not in text
    assert BLOCK_MARKER in text
    assert counts.get("private_key") == 1


@pytest.mark.parametrize("width", [58, 64, 70, 76, 80])
def test_key_lines_of_any_common_width_are_removed(width):
    lines = key_lines(width=width)

    text, _ = redact_text(pem(lines, end=False))

    assert leaked(text, lines) == []


def test_a_json_escaped_key_is_removed():
    body = json.dumps({"k": pem(LINES) + "\n"}).replace("/", "\\/")
    escaped = [line.replace("/", "\\/") for line in LINES]

    text, _ = redact_text(body)

    assert leaked(text, escaped) == []


def test_text_after_a_terminated_block_survives():
    text, _ = redact_text(pem(LINES) + "\n<p>after the key</p>")

    assert "after the key" in text


def test_an_orphan_end_line_takes_the_key_lines_above_it():
    """BEGIN lost (e.g. to a truncation gap): the END line and the key above it go."""
    text, _ = redact_text("<p>x</p>\n" + "\n".join(LINES) + "\n-----END RSA PRIVATE KEY-----")

    assert leaked(text) == []
    assert "<p>x</p>" in text


def test_a_run_of_bare_key_lines_is_removed_from_an_http_body():
    text, _ = redact_text("intro\n" + "\n".join(LINES) + "\noutro")

    assert leaked(text) == []


# --- the carve-out: public key material is kept (ADR-028 clause 2) ------------


@pytest.mark.parametrize("label", ["CERTIFICATE", "PUBLIC KEY", "RSA PUBLIC KEY", "X509 CRL"])
def test_public_pem_blocks_are_kept_whole(label):
    block = pem(LINES, label=label)

    text, counts = redact_text("<pre>" + block + "</pre>")

    assert block in text
    assert counts == {}


def test_a_certificate_chain_beside_a_private_key_keeps_the_certificate():
    cert = pem(key_lines(seed=7), label="CERTIFICATE")
    text, _ = redact_text(cert + "\n" + pem(LINES))

    assert cert in text
    assert leaked(text) == []


def test_without_heuristics_a_dkim_public_key_survives():
    """DNS records and certificate strings get token patterns only (clause 2)."""
    record = "v=DKIM1; k=rsa; p=" + "".join(LINES)

    assert redact_text(record, heuristics=False) == (record, {})


def test_without_heuristics_bare_base64_lines_survive():
    text = "\n".join(LINES)

    assert redact_text(text, heuristics=False)[0] == text


def test_without_heuristics_tokens_and_private_key_blocks_are_still_removed():
    text, counts = redact_text(f"{AWS} " + pem(LINES), heuristics=False)

    assert AWS not in text and leaked(text) == []
    assert counts == {"aws_access_key_id": 1, "private_key": 1}


def test_a_public_verification_token_survives():
    record = "google-site-verification=3TXzaCVZBuGyNiRhvtXkIYzMBAwxXtyHUOPIo1y9yLM"

    assert redact_text(record, heuristics=False)[0] == record
    assert redact_text(record)[0] == record


# --- running redaction again is safe (clause 7) ------------------------------


@pytest.mark.parametrize(
    "text",
    [
        pem(LINES) + "\nafter",
        pem(LINES, end=False),
        f"a {AWS} b " + pem(LINES, sep="<br>") + " c",
        "intro\n" + "\n".join(LINES) + "\noutro",
    ],
)
def test_redacting_twice_is_the_same_as_once(text):
    once, _ = redact_text(text)

    assert redact_text(once) == (once, {})


def test_the_new_block_marker_never_starts_a_cut():
    once, _ = redact_text(pem(LINES) + "\n<p>keep me</p>")

    assert "keep me" in redact_text(once)[0]


def test_the_legacy_marker_starts_a_cut():
    """Old core left `[redacted]:private_key` in place of BEGIN and kept the body."""
    legacy = f"{LEGACY_KEY_MARKER}\n" + "\n".join(LINES) + "\n-----END RSA PRIVATE KEY-----\nafter"

    text, counts = redact_text(legacy)

    assert leaked(text) == []
    assert "after" in text
    assert counts.get("private_key") == 1


# --- redact first, then truncate (clause 4) ----------------------------------


@pytest.mark.parametrize("cap", [400, 700, 1000, 1500])
@pytest.mark.parametrize("pre", [300, 900, 1000, 1100, 1300])
def test_a_key_straddling_any_cut_never_survives_capping(cap, pre):
    body = "x" * pre + "\n" + pem(LINES) + "\n" + "y" * 40

    text, truncated = cap_text(body, cap)

    assert leaked(text) == []
    assert "END RSA PRIVATE KEY" not in text
    assert len(text) <= cap + 64  # the gap note may add a few characters
    assert truncated == (len(redact_text(body)[0]) > cap)


@pytest.mark.parametrize(("kind", "secret"), list(TOKENS.items()))
def test_a_token_cut_by_the_cap_leaves_no_prefix(kind, secret):
    """The cap's cut lands at every position inside the secret. Whatever survives
    must not include any 8-character run of it."""
    for cut in range(1, len(secret)):
        body = "x" * (100 - cut) + " " + secret + " " + "y" * 400
        text, _ = cap_text(body, 200)
        runs = {secret[i : i + 8] for i in range(len(secret) - 7)}
        assert not any(run in text for run in runs), (kind, cut)


def test_capping_redacts_before_it_counts_length():
    body = AWS + " " + "z" * 10

    text, truncated = cap_text(body, 40)

    assert AWS not in text and not truncated


# --- hostile input (T7) ------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        ("\n... [5 bytes truncated] ...\n" + "-----END RSA PRIVATE KEY-----") * 4000,
        "-----BEGIN RSA PRIVATE KEY-----" * 8000,
        ("-----BEGIN RSA PRIVATE KEY-----" + "-----END RSA PRIVATE KEY-----") * 4000,
        ("A" * 64 + "\n") * 4000,
    ],
    ids=["note+END", "many BEGIN", "BEGIN END pairs", "base64 column"],
)
def test_hostile_input_is_redacted_in_linear_time(hostile):
    import time

    started = time.perf_counter()
    redact_text(hostile)

    assert time.perf_counter() - started < 0.5
