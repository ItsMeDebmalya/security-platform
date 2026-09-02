"""docs/03-roadmap.md 0b.6, exercised through the real `scan` CLI.

Passive is what an ordinary client does; active is deliberately abnormal
input. Email is pure DNS in every mode, and TLS is ordinary negotiation in
every mode (ADR-023) - reading a certificate, a protocol version, a cipher
choice - so neither is gated in any mode, matching docs/00-context.md's
product-wide contract that Light "may be pointed at anything" and matching
what the whole market does with TLS unauthenticated. The active path stays
enforced deny-by-default for the first tool that actually sends payloads.

Uses the same frozen corpus fixtures the gate itself replays, so this is a
real run through `cli/main.py`, not a mock.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
EMPTY_SCOPE = ROOT / "corpus" / "authz" / "__does_not_exist__.yaml"


def _run(*args: str):
    return runner.invoke(app, list(args))


def test_tls_light_mode_still_needs_no_authorisation() -> None:
    # The product-wide contract (docs/00-context.md): Light "may be pointed
    # at anything" (docs/13-test-targets.md). A per-check declaration must
    # not break this - every Light-tier TLS check is an ordinary handshake.
    result = _run(
        "run",
        "tls",
        "--target",
        "https://localhost:14400",
        "--mode",
        "light",
        "--replay",
        "corpus/fixtures/tls/healthy",
        "--scope-file",
        str(EMPTY_SCOPE),
    )

    assert result.exit_code == 0, result.stdout


def test_tls_standard_mode_also_needs_no_authorisation() -> None:
    # ADR-023: the protocol/cipher enumeration checks Standard adds are
    # ordinary negotiation, not malformed input - the whole market runs them
    # unauthenticated (SSL Labs, SSL.org, Mozilla). So TLS Standard, like
    # Light and like email, runs with no record. This reverses the 0b.6 first
    # cut that gated it; see docs/14-progress-ledger.md.
    result = _run(
        "run",
        "tls",
        "--target",
        "https://localhost:14400",
        "--mode",
        "standard",
        "--replay",
        "corpus/fixtures/tls/healthy",
        "--scope-file",
        str(EMPTY_SCOPE),
    )

    assert result.exit_code == 0, result.stdout


def test_email_standard_mode_no_longer_needs_authorisation() -> None:
    result = _run(
        "run",
        "email",
        "--target",
        "corpus-good.example",
        "--mode",
        "standard",
        "--replay",
        "corpus/fixtures/email/known-good",
        "--scope-file",
        str(EMPTY_SCOPE),
    )

    assert result.exit_code == 0, result.stdout


def test_email_light_mode_still_needs_no_authorisation() -> None:
    result = _run(
        "run",
        "email",
        "--target",
        "corpus-good.example",
        "--mode",
        "light",
        "--replay",
        "corpus/fixtures/email/known-good",
        "--scope-file",
        str(EMPTY_SCOPE),
    )

    assert result.exit_code == 0, result.stdout
