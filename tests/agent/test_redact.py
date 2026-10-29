"""B3: agent/redact.py has its own pattern set, a superset of core's."""

from agent import redact
from core import redaction as core_redaction


def test_pattern_families_are_a_superset_of_core():
    agent = {name: p.pattern for name, p in redact.SECRET_PATTERNS}
    for name, pattern in core_redaction.SECRET_PATTERNS:
        assert name in agent, name
        assert agent[name] == pattern.pattern, name


def test_markers_match_core():
    assert redact.REDACTED == core_redaction.REDACTED
    assert redact.BLOCK_MARKER == core_redaction.BLOCK_MARKER


def test_behaves_like_core_on_planted_secrets():
    secrets = [
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + "a" * 30,
        "Bearer abcdefghijklmnop1234",
        "xoxb-1234567890-abc",
        "AIza" + "B" * 35,
    ]
    for s in secrets:
        text = "key=" + s + " end"
        out, counts = redact.redact_text(text)
        assert s not in out and counts
        assert out == core_redaction.redact_text(text)[0]


def test_private_key_block_removed_and_public_kept():
    priv = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    out, counts = redact.redact_text("a\n" + priv + "\nb")
    assert "MIIabc" not in out and counts["private_key"] == 1
    cert = "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----"
    assert redact.redact_text(cert)[0] == cert
    out, _ = redact.redact_text("-----BEGIN PRIVATE KEY-----\nMIIabc\nno end")
    assert "MIIabc" not in out


def test_idempotent():
    once, _ = redact.redact_text("x AKIAABCDEFGHIJKLMNOP y")
    assert redact.redact_text(once)[0] == once


def test_redact_data_walks_json():
    out = redact.redact_data({"k": ["AKIAABCDEFGHIJKLMNOP"], "n": 3})
    assert "AKIA" not in str(out) and out["n"] == 3


def test_parity_on_private_key_shapes():
    shapes = [
        "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nb",
        "a\r\n-----BEGIN PRIVATE KEY-----\r\nMIIabc\r\n-----END PRIVATE KEY-----\r\nb",
        "a\\n-----BEGIN OPENSSH PRIVATE KEY-----\\nMIIabc\\n-----END OPENSSH PRIVATE KEY-----\\nb",
        "-----BEGIN PRIVATE KEY-----\nMIIabc\nno end",
    ]
    for text in shapes:
        out, _ = redact.redact_text(text)
        assert "MIIabc" not in out
        assert out == core_redaction.redact_text(text)[0]


def test_known_gap_bare_base64_run_is_not_yet_redacted():
    """Spec 6.3 base64 deny-list is owed. Core cuts this run; the agent does not yet.
    When the agent gains the deny-list, flip this test deliberately."""
    blob = "\n".join(["A" * 64, "B" * 64, "C" * 64])
    assert core_redaction.redact_text(blob)[0] != blob
    assert redact.redact_text(blob)[0] == blob
