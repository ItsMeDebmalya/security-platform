"""Licence policy check. Run by CI; fails the build rather than a review.

ADR-003: permissive open source may be embedded; commercial, restrictive or
legally unclear may not - we build the capability ourselves and import the
other tool's output instead.

Two automated rules:

1. Every direct dependency and every third-party binary appears in
   `tools/registry.yaml` with a licence, a pinned version and a sign-off.
2. Anything copyleft is declared `subprocess` or `service`, never `library`.
   GPL tools run as separate processes only - never linked, never copied.

Transitive dependencies are not covered here. The lockfile pins them, and a
transitive-licence sweep is a Phase 6 task; saying so is better than implying
a coverage we do not have.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "tools" / "registry.yaml"
PYPROJECT_PATH = ROOT / "pyproject.toml"

APPROVED_SPDX = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "PSF-2.0",
        "MPL-2.0",
        "Unlicense",
        "CC0-1.0",
        "public-data",
    }
)
"""Embeddable. Anything not on this list needs an ADR before it enters the tree."""

ISOLATION_REQUIRED_SPDX = frozenset(
    {
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "LGPL-2.1-only",
        "LGPL-3.0-only",
    }
)
"""Usable, but only at arm's length. LGPL is included: linking carries conditions
we do not want to argue about, so we treat it exactly like GPL."""

ISOLATED_MODES = frozenset({"subprocess", "service"})

FORBIDDEN_TOOLS = frozenset(
    {
        "nmap",
        "nessus",
        "burp",
        "burpsuite",
        "acunetix",
        "invicti",
        "semgrep",
        "trufflehog",
        "openvas",
        "greenbone",
        "metasploit",
        "wappalyzer",
    }
)
"""Never, whatever licence an entry claims. See ADR-003's forbidden table.
`wappalyzer` is here because its fingerprint database is GPL-3.0 - a data
licence surface, not only a code one."""

REQUIRED_FIELDS = ("name", "version", "licence", "spdx", "source", "purpose", "isolation")


def load_registry(path: Path = REGISTRY_PATH) -> list[dict[str, Any]]:
    return list(yaml.safe_load(path.read_text()) or [])


def direct_dependencies() -> set[str]:
    """Direct runtime and dev dependencies, by distribution name."""
    data = tomllib.loads(PYPROJECT_PATH.read_text())
    specs: list[str] = list(data["project"].get("dependencies", []))
    for group in data.get("dependency-groups", {}).values():
        specs.extend(group)
    names = set()
    for spec in specs:
        name = spec.split(";")[0]
        for separator in (">=", "==", "<=", "~=", ">", "<", "["):
            name = name.split(separator)[0]
        names.add(name.strip().lower())
    return names


def check_registry(registry: list[dict[str, Any]]) -> list[str]:
    """Return every policy violation. An empty list means the build may proceed."""
    problems: list[str] = []
    for entry in registry:
        name = str(entry.get("name", "<unnamed>"))
        missing = [f for f in REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            problems.append(f"{name}: registry entry is missing {', '.join(missing)}")
            continue

        spdx = str(entry["spdx"])
        isolation = str(entry["isolation"])

        if name.lower() in FORBIDDEN_TOOLS:
            problems.append(
                f"{name}: forbidden by ADR-003 regardless of the licence claimed here. "
                "We build the capability ourselves and import its output instead."
            )
        elif spdx in ISOLATION_REQUIRED_SPDX:
            if isolation not in ISOLATED_MODES:
                problems.append(
                    f"{name}: {spdx} must be declared subprocess or service, not "
                    f"{isolation!r}. GPL code is never linked into our tree."
                )
        elif spdx not in APPROVED_SPDX:
            problems.append(
                f"{name}: {spdx} is not on the approved licence list. "
                "Raise it as an open question rather than adding it."
            )

        if isolation not in ISOLATED_MODES | {"library", "data"}:
            problems.append(f"{name}: unknown isolation mode {isolation!r}")

    return problems


def main() -> int:
    registry = load_registry()
    problems = check_registry(registry)

    registered = {str(e.get("name", "")).lower() for e in registry}
    missing = sorted(dep for dep in direct_dependencies() if dep not in registered)
    problems.extend(
        f"{dep}: a direct dependency with no entry in tools/registry.yaml" for dep in missing
    )

    if problems:
        print("Licence policy violations:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"licence check: {len(registry)} registered components, no violations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
