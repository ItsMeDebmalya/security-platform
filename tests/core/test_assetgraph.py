"""ADR-019: the asset graph. Provenance is mandatory, authorisation is
re-checked per asset, and consuming is optional.
"""

from __future__ import annotations

from datetime import date

import pytest

from core.assetgraph import AssetGraph, DiscoveredAsset, seed_asset_graph
from core.authz import AuthorisationRecord, AuthorisedScope
from core.context import ScanContext
from core.models import Asset


def _asset(value: str = "api.example.com") -> Asset:
    return Asset(type="domain", value=value)


class TestProvenanceIsMandatory:
    def test_discovered_asset_requires_discovered_by(self) -> None:
        with pytest.raises(TypeError):
            DiscoveredAsset(  # type: ignore[call-arg]
                asset=_asset(), evidence="finding sha256:" + "0" * 64, check_id="dns-enum"
            )

    def test_discovered_asset_requires_evidence(self) -> None:
        with pytest.raises(TypeError):
            DiscoveredAsset(  # type: ignore[call-arg]
                asset=_asset(), discovered_by="dns_enum", check_id="dns-enum"
            )

    def test_discovered_asset_requires_check_id(self) -> None:
        with pytest.raises(TypeError):
            DiscoveredAsset(  # type: ignore[call-arg]
                asset=_asset(), discovered_by="dns_enum", evidence="a CNAME chain"
            )

    def test_fully_provenanced_asset_constructs_and_is_contributable(self) -> None:
        discovered = DiscoveredAsset(
            asset=_asset(),
            discovered_by="dns_enum",
            evidence="a CNAME chain",
            check_id="subdomain-enum",
        )
        graph = AssetGraph()
        graph.contribute(discovered)
        assert graph.all() == [discovered]


class TestGraphIsReadableAndFilterable:
    def test_by_scanner_and_by_type(self) -> None:
        graph = AssetGraph()
        graph.contribute(
            DiscoveredAsset(
                asset=Asset(type="domain", value="a.example.com"),
                discovered_by="dns_enum",
                evidence="zone walk",
                check_id="subdomain-enum",
            )
        )
        graph.contribute(
            DiscoveredAsset(
                asset=Asset(type="ip", value="203.0.113.9"),
                discovered_by="dns_enum",
                evidence="A record for a.example.com",
                check_id="subdomain-enum",
            )
        )
        graph.contribute(
            DiscoveredAsset(
                asset=Asset(type="domain", value="b.example.com"),
                discovered_by="tls",
                evidence="SAN entry on a.example.com's certificate",
                check_id="tls-san-domains",
            )
        )
        assert len(graph.by_scanner("dns_enum")) == 2
        assert len(graph.by_type("domain")) == 2
        assert len(graph) == 3


class TestConsumingIsOptional:
    def test_scancontext_defaults_to_an_empty_graph(self) -> None:
        ctx = ScanContext()
        assert ctx.assets.all() == []

    def test_a_scancontext_built_without_assets_kwarg_is_unaffected(self) -> None:
        # Every scanner written before this task constructs ScanContext this
        # way (see cli/main.py, scanners/*/tests). If this silently required
        # a graph, every one of them would break at construction time.
        ctx = ScanContext(scan_id="01J8TESTTESTTESTTESTTESTTE", org_id="org_internal")
        assert isinstance(ctx.assets, AssetGraph)
        assert len(ctx.assets) == 0


class TestAuthorisationIsReCheckedPerAsset:
    """Discovery does not confer permission. A wildcard authorisation for
    example.com covers a genuinely-discovered subdomain, but not a name
    enumeration merely guessed that happens to resolve to something on the
    internet the org does not own.
    """

    def _scope(self) -> AuthorisedScope:
        record = AuthorisationRecord(
            authz_id="authz_1",
            org_id="org_internal",
            target_type="domain",
            target_value="example.com",
            wildcard=True,
            method="dns_txt",
            expires_at=date(2099, 1, 1),
            evidence_file="proof.txt",
        )
        return AuthorisedScope([record])

    def test_discovered_asset_under_the_wildcard_is_authorised(self) -> None:
        scope = self._scope()
        discovered = DiscoveredAsset(
            asset=Asset(type="domain", value="api.example.com"),
            discovered_by="dns_enum",
            evidence="CNAME chain from example.com",
            check_id="subdomain-enum",
        )
        decision = scope.authorise(discovered.asset, mode="standard")
        assert decision.allowed

    def test_discovered_asset_outside_the_authorised_domain_is_denied(self) -> None:
        # The scenario ADR-019 names directly: enumeration guessed a name
        # that happens to resolve, but it is not under the authorised host.
        scope = self._scope()
        discovered = DiscoveredAsset(
            asset=Asset(type="domain", value="unrelated-corp.net"),
            discovered_by="dns_enum",
            evidence="a wildcard DNS answer",
            check_id="subdomain-enum",
        )
        decision = scope.authorise(discovered.asset, mode="standard")
        assert not decision.allowed

    def test_the_graph_itself_exposes_no_authorisation_method(self) -> None:
        # Structural check that this module cannot become a second gate:
        # AssetGraph has no authorise/permits/covers method for anything to
        # call instead of core/authz.py.
        for name in ("authorise", "permits", "covers", "require"):
            assert not hasattr(AssetGraph, name)


class TestSeedAssetGraphForReplay:
    """The corpus-harness seam: a consuming scanner is testable without
    running its producer.
    """

    def test_seeds_a_graph_from_plain_dicts(self) -> None:
        graph = seed_asset_graph(
            [
                {
                    "asset": {"type": "domain", "value": "api.example.com"},
                    "discovered_by": "dns_enum",
                    "evidence": "CNAME chain",
                    "check_id": "subdomain-enum",
                }
            ]
        )
        assert len(graph) == 1
        only = graph.all()[0]
        assert only.asset.value == "api.example.com"
        assert only.discovered_by == "dns_enum"

    def test_empty_seed_gives_an_empty_graph(self) -> None:
        assert len(seed_asset_graph([])) == 0

    def test_seed_row_missing_provenance_raises(self) -> None:
        with pytest.raises(KeyError):
            seed_asset_graph(
                [{"asset": {"type": "domain", "value": "api.example.com"}, "check_id": "x"}]
            )
