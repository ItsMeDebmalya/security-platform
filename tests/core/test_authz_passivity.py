"""docs/03-roadmap.md 0b.6: the ownership gate enforces a per-check
declaration, not mode alone.

Deny-by-default must survive intact: a check with no declaration is active,
never passive, and `passive=None` (no opinion) must never widen what `light`
mode was already allowed to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from core.authz import AuthorisedScope, checks_require_authorisation
from core.models import Asset

TODAY = date(2026, 8, 28)


@dataclass(frozen=True)
class _FakeCheck:
    passive: bool
    mode: str = "light"


class TestChecksRequireAuthorisation:
    def test_all_passive_light_checks_need_no_authorisation(self) -> None:
        checks = [_FakeCheck(passive=True), _FakeCheck(passive=True, mode="standard")]
        assert checks_require_authorisation(checks, mode="light") is False
        assert checks_require_authorisation(checks, mode="standard") is False

    def test_one_active_light_check_requires_authorisation_even_in_light_mode(self) -> None:
        # The gap named directly in the roadmap: a Light check can be active.
        checks = [_FakeCheck(passive=False), _FakeCheck(passive=True)]
        assert checks_require_authorisation(checks, mode="light") is True

    def test_an_active_standard_only_check_does_not_taint_light_mode(self) -> None:
        # A check that would not even run in light mode must not force
        # authorisation for a light-mode scan.
        checks = [
            _FakeCheck(passive=True, mode="light"),
            _FakeCheck(passive=False, mode="standard"),
        ]
        assert checks_require_authorisation(checks, mode="light") is False
        assert checks_require_authorisation(checks, mode="standard") is True

    def test_no_checks_needs_no_authorisation(self) -> None:
        assert checks_require_authorisation([], mode="standard") is False


class TestAuthoriseHonoursThePassiveDeclaration:
    def _target(self) -> Asset:
        return Asset(type="domain", value="unauthorised.example")

    def test_passive_true_allows_light_with_no_record(self) -> None:
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="light", passive=True, today=TODAY)
        assert decision.allowed

    def test_passive_true_allows_standard_with_no_record(self) -> None:
        # The other half of the gap: email Standard is genuinely passive and
        # must not need a record any more than Light does.
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="standard", passive=True, today=TODAY)
        assert decision.allowed

    def test_passive_false_denies_light_with_no_record(self) -> None:
        # The other half: TLS Light makes a handshake and must now be
        # gated even though it runs under the label "light".
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="light", passive=False, today=TODAY)
        assert not decision.allowed

    def test_passive_false_denies_standard_with_no_record(self) -> None:
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="standard", passive=False, today=TODAY)
        assert not decision.allowed

    def test_passive_none_falls_back_to_legacy_mode_rule_for_light(self) -> None:
        # A scanner that has not declared anything (the reference `example`
        # scanner) must behave exactly as it did before this task.
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="light", passive=None, today=TODAY)
        assert decision.allowed

    def test_passive_none_falls_back_to_legacy_mode_rule_for_standard(self) -> None:
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="standard", passive=None, today=TODAY)
        assert not decision.allowed

    def test_omitting_passive_entirely_is_the_same_as_none(self) -> None:
        scope = AuthorisedScope([])
        decision = scope.authorise(self._target(), mode="light", today=TODAY)
        assert decision.allowed


class TestScannerCatalogueDeclarations:
    """Every check in email and tls, classified on what it actually does."""

    def test_email_is_pure_dns_and_never_requires_authorisation(self) -> None:
        from scanners.email.checks import CHECKS, requires_authorisation

        assert all(c.passive for c in CHECKS.values())
        assert requires_authorisation("light") is False
        assert requires_authorisation("standard") is False
        assert requires_authorisation("deep") is False

    def test_tls_light_checks_are_an_ordinary_handshake_and_need_no_authorisation(self) -> None:
        # docs/00-context.md's product-wide contract: Light is passive and
        # "may be pointed at anything" (docs/13-test-targets.md). Every
        # Light-tier TLS check reads what an ordinary client's handshake
        # already sees - the same certificate a browser gets - so this must
        # stay False, not True, or Tool 2 has no Light mode at all.
        from scanners.tls.checks import CHECKS, requires_authorisation

        light_checks = [c for c in CHECKS.values() if c.mode == "light"]
        assert light_checks and all(c.passive for c in light_checks)
        assert requires_authorisation("light") is False

    def test_tls_standard_mode_needs_authorisation_only_because_of_its_active_checks(self) -> None:
        # The three checks that force deliberately abnormal input - offering
        # obsolete protocols or weak/legacy ciphers to see what the server
        # will accept, rather than what it ordinarily negotiates - are
        # active. The other three Standard checks read straight off the
        # certificate and are passive, exactly like the Light ones: some
        # Standard checks being passive is 0b.6 working as intended, the
        # same shape as email's Standard checks all being passive.
        from scanners.tls.checks import CHECKS, requires_authorisation

        active = {c.check_id for c in CHECKS.values() if not c.passive}
        assert active == {"tls-protocol-obsolete", "tls-weak-cipher", "tls-no-forward-secrecy"}

        passive_standard = {"tls-weak-key", "tls-weak-signature", "tls-no-certificate-transparency"}
        assert all(CHECKS[cid].passive for cid in passive_standard)

        assert requires_authorisation("standard") is True
        assert requires_authorisation("deep") is True

    def test_every_check_in_both_catalogues_declares_passivity(self) -> None:
        # A structural guard against a check being added with no opinion -
        # `passive` has no default, so this would already fail to import if
        # violated, but assert it explicitly as living documentation.
        from scanners.email.checks import CHECKS as EMAIL_CHECKS
        from scanners.tls.checks import CHECKS as TLS_CHECKS

        for catalogue in (EMAIL_CHECKS, TLS_CHECKS):
            for check in catalogue.values():
                assert isinstance(check.passive, bool)


class TestBaseScannerDefaultIsUnaffected:
    def test_a_scanner_that_does_not_override_returns_none(self) -> None:
        from core.registry import discover

        example = discover().get("example")()
        assert example.requires_authorisation("light") is None
        assert example.requires_authorisation("standard") is None
