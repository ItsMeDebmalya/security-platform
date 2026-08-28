"""The correlation pass (ADR-022 "connect", docs/03-roadmap.md 0b.9).

Covers the rules loader's strict validation and the pass's two hardest
invariants: confidence is inherited from the weakest premise, never
recomputed, and a rule with only some of its premises satisfied emits
nothing - never a hedged story.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.assetgraph import AssetGraph, DiscoveredAsset
from core.correlation import (
    CompositionRule,
    CorrelationRulesError,
    correlate,
    load_composition_rules,
)
from core.models import Asset

GOOD_RULES = """
- id: spoofable-plus-weak-tls
  title: "Spoofable domain with obsolete TLS"
  premises:
    - scanner: email
      check_id: spoofing-possible
    - scanner: tls
      check_id: tls-protocol-obsolete
  conclusion:
    title: "Spoofable domain also runs obsolete TLS"
    severity: high
    description: "Both weaknesses attack the same trust relationship."
    impact: "Combines phishing with transport interception."
    remediation: "Fix either premise to break the chain."
  why: "Both premises are checks we already ship at gate."
  reviewed_by: satwik
  reviewed_at: 2026-08-28
"""


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(content)
    return path


class TestLoaderIsStrictAndLoud:
    def test_a_well_formed_rule_loads(self, tmp_path: Path) -> None:
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        assert len(rules) == 1
        assert isinstance(rules[0], CompositionRule)
        assert rules[0].id == "spoofable-plus-weak-tls"

    def test_missing_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CorrelationRulesError):
            load_composition_rules(tmp_path / "does-not-exist.yaml")

    def test_a_rule_missing_why_fails_loudly(self, tmp_path: Path) -> None:
        bad = GOOD_RULES.replace('why: "Both premises are checks we already ship at gate."\n', "")
        with pytest.raises(CorrelationRulesError):
            load_composition_rules(_write(tmp_path, bad))

    def test_a_single_premise_rule_fails_loudly(self, tmp_path: Path) -> None:
        """A 'rule' with one premise is not a composition - it restates a
        single finding and does not belong in this file."""
        bad = """
- id: one-premise
  title: "Not a composition"
  premises:
    - scanner: email
      check_id: spoofing-possible
  conclusion:
    title: "x"
    severity: high
    description: "x"
    impact: "x"
    remediation: "x"
  why: "x"
  reviewed_by: satwik
  reviewed_at: 2026-08-28
"""
        with pytest.raises(CorrelationRulesError):
            load_composition_rules(_write(tmp_path, bad))

    def test_duplicate_rule_id_fails_loudly(self, tmp_path: Path) -> None:
        with pytest.raises(CorrelationRulesError):
            load_composition_rules(_write(tmp_path, GOOD_RULES + GOOD_RULES))

    def test_not_a_list_fails_loudly(self, tmp_path: Path) -> None:
        with pytest.raises(CorrelationRulesError):
            load_composition_rules(_write(tmp_path, "id: not-a-list\n"))

    def test_the_shipped_rules_file_loads(self) -> None:
        rules = load_composition_rules()
        assert len(rules) >= 2
        for rule in rules:
            assert len(rule.premises) >= 2


class TestCorrelationPass:
    def test_both_premises_present_emits_one_inherited_story(self, make_finding, tmp_path) -> None:
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        email_finding = make_finding(
            scanner="email",
            check_id="spoofing-possible",
            confidence=0.90,
        )
        tls_finding = make_finding(
            scanner="tls",
            check_id="tls-protocol-obsolete",
            confidence=0.55,  # the weakest link
        )
        target = Asset(type="domain", value="example.com")

        stories = correlate(
            findings=[email_finding, tls_finding],
            asset_graph=AssetGraph(),
            primary_target=target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000000",
            rules=rules,
            now=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        )

        assert len(stories) == 1
        story = stories[0]
        assert story.derivation == "derived"
        assert story.check_id == "spoofable-plus-weak-tls"
        assert set(story.derived_from.split(",")) == {email_finding.id, tls_finding.id}
        # confidence is inherited from the WEAKEST premise, never combined/recomputed
        assert story.confidence == min(email_finding.confidence, tls_finding.confidence)
        assert story.confidence == 0.55

    def test_partial_premises_emit_nothing(self, make_finding, tmp_path) -> None:
        """Under-telling beats over-telling: a rule with only one of two
        premises present must emit no story at all - never a hedged one."""
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        email_finding = make_finding(scanner="email", check_id="spoofing-possible")
        # no tls-protocol-obsolete finding present
        target = Asset(type="domain", value="example.com")

        stories = correlate(
            findings=[email_finding],
            asset_graph=AssetGraph(),
            primary_target=target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000001",
            rules=rules,
        )

        assert stories == []

    def test_premises_on_different_assets_do_not_compose(self, make_finding, tmp_path) -> None:
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        email_finding = make_finding(
            scanner="email",
            check_id="spoofing-possible",
            target={"type": "domain", "value": "a.example.com"},
        )
        tls_finding = make_finding(
            scanner="tls",
            check_id="tls-protocol-obsolete",
            target={"type": "domain", "value": "b.example.com"},
        )
        target = Asset(type="domain", value="a.example.com")

        stories = correlate(
            findings=[email_finding, tls_finding],
            asset_graph=AssetGraph(),
            primary_target=target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000002",
            rules=rules,
        )

        assert stories == []

    def test_inconclusive_premises_do_not_count(self, make_finding, tmp_path) -> None:
        """`inconclusive` means no verdict was reached at all - composing that
        into a story would manufacture certainty from not knowing, exactly
        the failure under-telling guards against. It must not seed a story."""
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        email_finding = make_finding(
            scanner="email",
            check_id="spoofing-possible",
            no_verdict_reason="timeout",  # -> state becomes 'inconclusive'
        )
        tls_finding = make_finding(scanner="tls", check_id="tls-protocol-obsolete")
        target = Asset(type="domain", value="example.com")

        stories = correlate(
            findings=[email_finding, tls_finding],
            asset_graph=AssetGraph(),
            primary_target=target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000003",
            rules=rules,
        )

        assert stories == []

    def test_informational_premises_do_count(self, make_finding, tmp_path) -> None:
        """`informational` is a resolved, true, evidenced observation - "true
        but not directly dangerous" (docs/01-architecture.md), not a hedge on
        an unresolved question. The shipped `expiring-cert-blind-to-renewal`
        rule depends on this: `tls-no-certificate-transparency` is always
        `severity: info` in the TLS scanner, by design, so a rule needing it
        as a premise would never fire if `informational` were excluded."""
        rules_text = """
- id: expiring-blind
  title: "Expiring cert with no CT trail"
  premises:
    - scanner: tls
      check_id: tls-cert-expiring-soon
    - scanner: tls
      check_id: tls-no-certificate-transparency
  conclusion:
    title: "Expiring soon, no CT trail to confirm renewal"
    severity: medium
    description: "x"
    impact: "x"
    remediation: "x"
  why: "x"
  reviewed_by: satwik
  reviewed_at: 2026-08-28
"""
        rules = load_composition_rules(_write(tmp_path, rules_text))
        expiring = make_finding(
            scanner="tls",
            check_id="tls-cert-expiring-soon",
            confidence=0.98,
        )
        no_ct = make_finding(
            scanner="tls",
            check_id="tls-no-certificate-transparency",
            severity="info",  # -> state becomes 'informational', by construction
            confidence=0.90,
        )
        target = Asset(type="domain", value="example.com")

        stories = correlate(
            findings=[expiring, no_ct],
            asset_graph=AssetGraph(),
            primary_target=target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000006",
            rules=rules,
        )

        assert len(stories) == 1
        assert stories[0].confidence == min(expiring.confidence, no_ct.confidence)

    def test_a_related_asset_needs_provenance_in_the_graph(self, make_finding, tmp_path) -> None:
        """A group of findings on an asset that is neither the run's primary
        target nor in the asset graph is not composed - ADR-019: an asset
        without provenance is a bug, not something this pass may act on."""
        rules = load_composition_rules(_write(tmp_path, GOOD_RULES))
        other_asset = {"type": "domain", "value": "other.example.com"}
        email_finding = make_finding(
            scanner="email", check_id="spoofing-possible", target=other_asset
        )
        tls_finding = make_finding(
            scanner="tls", check_id="tls-protocol-obsolete", target=other_asset
        )
        primary_target = Asset(type="domain", value="example.com")

        # not provenanced: no story
        assert (
            correlate(
                findings=[email_finding, tls_finding],
                asset_graph=AssetGraph(),
                primary_target=primary_target,
                org_id="org_internal",
                scan_id="01J8STORY0000000000000004",
                rules=rules,
            )
            == []
        )

        # provenanced via the asset graph: now it composes
        graph = AssetGraph(
            [
                DiscoveredAsset(
                    asset=Asset(**other_asset),
                    discovered_by="dns_enum",
                    evidence="zone walk",
                    check_id="subdomain-enum",
                )
            ]
        )
        stories = correlate(
            findings=[email_finding, tls_finding],
            asset_graph=graph,
            primary_target=primary_target,
            org_id="org_internal",
            scan_id="01J8STORY0000000000000005",
            rules=rules,
        )
        assert len(stories) == 1
