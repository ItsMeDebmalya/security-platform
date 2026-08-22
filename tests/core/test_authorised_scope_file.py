"""The committed allowlist must load, and must not silently authorise anything."""

from __future__ import annotations

from pathlib import Path

from core.authz import AuthorisedScope
from core.models import Asset

SCOPE_PATH = Path(__file__).resolve().parents[2] / "config" / "authorised_scope.yaml"


def test_the_committed_scope_file_exists_and_parses():
    AuthorisedScope.load(SCOPE_PATH)


def test_the_committed_scope_file_denies_standard_mode_for_an_unlisted_target():
    scope = AuthorisedScope.load(SCOPE_PATH)

    decision = scope.authorise(Asset(type="domain", value="example.com"), mode="standard")

    assert not decision.allowed


def test_the_committed_scope_file_still_permits_light_mode():
    scope = AuthorisedScope.load(SCOPE_PATH)

    assert scope.authorise(Asset(type="domain", value="example.com"), mode="light").allowed
