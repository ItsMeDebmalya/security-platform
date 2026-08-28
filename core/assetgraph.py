"""The asset graph — ADR-019: scanners exchange assets through the run,
never through each other.

A `ScanRun` carries one shared `AssetGraph`. A scanner that discovers
something new during a scan (Tool 3's whole purpose) contributes it here;
a later scanner in the same run may read what has been found so far. Both
happen through `ScanContext` — never by importing another scanner — which is
what keeps every scanner replaceable and testable alone (docs/01-architecture.md,
"The asset graph").

Two rules the ADR makes non-negotiable, both enforced here rather than left
to convention:

- **Provenance is mandatory.** "An asset that appeared without provenance is
  a bug, not a discovery." `DiscoveredAsset` has no default for
  `discovered_by` or `evidence`, so the object cannot be constructed without
  them — this is a dataclass field requirement, not a runtime check that a
  careless caller could skip.
- **The graph confers no authorisation.** It is data, not a widened scope.
  `core/authz.py` is the only gate, and it is asked again for every asset a
  scanner means to actively touch, exactly as it is for the run's original
  target. Nothing in this module talks to `core/authz.py` at all — that
  silence is deliberate: an asset graph that granted scope would be the
  fastest way to bypass the gate, and the surest way to do that is to never
  give this module the means.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Asset


@dataclass(frozen=True)
class DiscoveredAsset:
    """One asset in the graph, with the provenance that explains it.

    `discovered_by` and `evidence` have no defaults on purpose: a
    `DiscoveredAsset` missing either fails to construct at all (`TypeError`,
    not a validation error caught later), so "an asset with no provenance"
    is not a state this type can hold rather than a rule enforced on it.
    """

    asset: Asset
    discovered_by: str
    """The scanner name that found this asset, e.g. `"dns_enum"`."""
    evidence: str
    """What justified it — typically the id of the finding that surfaced it,
    or a short description when no finding was involved (an enumerated name
    that resolved, say)."""
    check_id: str
    """The check that produced it, for the same reason a finding carries one."""
    instance_key: str | None = None


class AssetGraph:
    """Assets discovered so far in this run.

    Consuming is optional: a scanner never asked to read this returns
    exactly the same results it would with an empty graph, because an empty
    graph *is* what a scanner handed no discoveries sees. Nothing about
    reading or ignoring the graph is order-dependent by accident.
    """

    def __init__(self, assets: list[DiscoveredAsset] | None = None) -> None:
        self._assets: list[DiscoveredAsset] = list(assets) if assets else []

    def contribute(self, discovered: DiscoveredAsset) -> None:
        """Add a discovered asset. Never call this for the scan's own target —
        that is the run's target, not a discovery, and belongs on `ScanRun`."""
        self._assets.append(discovered)

    def all(self) -> list[DiscoveredAsset]:
        return list(self._assets)

    def by_scanner(self, discovered_by: str) -> list[DiscoveredAsset]:
        return [a for a in self._assets if a.discovered_by == discovered_by]

    def by_type(self, asset_type: str) -> list[DiscoveredAsset]:
        return [a for a in self._assets if a.asset.type == asset_type]

    def __len__(self) -> int:
        return len(self._assets)


def seed_asset_graph(rows: list[dict[str, object]]) -> AssetGraph:
    """Build a graph from plain dicts — the corpus harness's replay seam.

    ADR-019's consequences call this out explicitly: "the corpus harness
    needs a way to seed a graph for replay, so a consuming scanner is
    testable without running its producer." A corpus case can carry a
    `seed_assets:` list shaped like this function's input and get a graph
    populated exactly as if a producer scanner had run first, with no
    producer actually run and no fixtures for one needed.
    """
    discovered = [
        DiscoveredAsset(
            asset=Asset(**row["asset"]),  # type: ignore[arg-type]
            discovered_by=str(row["discovered_by"]),
            evidence=str(row["evidence"]),
            check_id=str(row["check_id"]),
            instance_key=(str(row["instance_key"]) if row.get("instance_key") else None),
        )
        for row in rows
    ]
    return AssetGraph(discovered)
