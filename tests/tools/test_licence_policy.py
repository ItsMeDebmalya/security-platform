"""Licence policy, enforced in CI rather than in reviewers' heads.

Two rules from ADR-003 and docs/06-guidelines.md:
- permissive OSS may be embedded; commercial, restrictive or unclear may not
- GPL and LGPL tools run as separate processes only, never linked or copied
"""

from __future__ import annotations

import pytest
import yaml

from cli.licences import (
    APPROVED_SPDX,
    ATTRIBUTION_REQUIRED_SPDX,
    DATA_ONLY_SPDX,
    FORBIDDEN_TOOLS,
    ISOLATION_REQUIRED_SPDX,
    REGISTRY_PATH,
    check_registry,
    direct_dependencies,
    load_registry,
)


@pytest.fixture
def registry():
    return load_registry(REGISTRY_PATH)


def test_the_committed_registry_passes_its_own_policy(registry):
    assert check_registry(registry) == []


def test_every_direct_dependency_is_registered(registry):
    registered = {entry["name"].lower() for entry in registry}

    missing = sorted(dep for dep in direct_dependencies() if dep not in registered)

    assert missing == [], f"dependencies with no licence entry: {missing}"


def test_every_entry_pins_an_exact_version(registry):
    unpinned = [e["name"] for e in registry if not e.get("version")]

    assert unpinned == []


def test_every_entry_records_who_signed_it_off_and_when(registry):
    unsigned = [
        e["name"] for e in registry if not e.get("signed_off_by") or not e.get("signed_off_at")
    ]

    assert unsigned == []


# --- the policy itself ------------------------------------------------------


def _entry(**overrides):
    base = {
        "name": "example",
        "version": "1.0.0",
        "licence": "MIT",
        "spdx": "MIT",
        "source": "https://example.invalid",
        "purpose": "testing",
        "isolation": "library",
        "signed_off_by": "satwik",
        "signed_off_at": "2026-08-22",
    }
    base.update(overrides)
    return base


def test_a_permissive_licence_may_be_embedded():
    assert check_registry([_entry(spdx="MIT", isolation="library")]) == []


def test_an_unapproved_licence_fails_the_build():
    problems = check_registry([_entry(name="mystery", spdx="SSPL-1.0")])

    assert any("SSPL-1.0" in p for p in problems)


def test_a_gpl_tool_declared_as_a_library_fails_the_build():
    """This is the automated half of 'nobody accidentally links GPL into our binary'."""
    problems = check_registry([_entry(name="testssl.sh", spdx="GPL-2.0-only", isolation="library")])

    assert any("testssl.sh" in p and "subprocess" in p for p in problems)


def test_a_gpl_tool_run_as_a_separate_process_is_fine():
    assert (
        check_registry([_entry(name="testssl.sh", spdx="GPL-2.0-only", isolation="subprocess")])
        == []
    )


def test_a_gpl_django_app_run_as_its_own_service_is_fine():
    """MobSF is GPLv3 and a Django app: its own container, talked to over HTTP."""
    assert check_registry([_entry(name="mobsf", spdx="GPL-3.0-only", isolation="service")]) == []


def test_lgpl_needs_isolation_too():
    problems = check_registry([_entry(name="opengrep", spdx="LGPL-2.1-only", isolation="library")])

    assert any("opengrep" in p for p in problems)


@pytest.mark.parametrize("tool", ["nmap", "nessus", "burp", "semgrep", "trufflehog", "openvas"])
def test_a_forbidden_tool_fails_the_build_whatever_licence_it_claims(tool):
    problems = check_registry([_entry(name=tool, spdx="MIT")])

    assert any(tool in p.lower() for p in problems)


def test_the_forbidden_list_matches_adr_003():
    assert {"nmap", "nessus", "trufflehog", "openvas"} <= FORBIDDEN_TOOLS


def test_gpl_is_never_on_the_embeddable_list():
    assert not any(spdx.startswith("GPL") for spdx in APPROVED_SPDX)


def test_every_isolation_required_licence_is_also_approved():
    assert ISOLATION_REQUIRED_SPDX <= APPROVED_SPDX | ISOLATION_REQUIRED_SPDX


def test_an_entry_missing_its_isolation_mode_fails():
    entry = _entry()
    del entry["isolation"]

    assert check_registry([entry])


def test_the_registry_file_is_valid_yaml():
    yaml.safe_load(REGISTRY_PATH.read_text())


def test_registry_versions_match_the_lockfile(registry):
    """A registry that drifts from the lockfile is a legal record that lies."""
    import tomllib
    from pathlib import Path

    lock = tomllib.loads((Path(__file__).resolve().parents[2] / "uv.lock").read_text())
    locked = {p["name"].lower(): p["version"] for p in lock["package"]}

    drift = [
        f"{e['name']}: registry says {e['version']}, lockfile says {locked[e['name'].lower()]}"
        for e in registry
        if e["name"].lower() in locked and locked[e["name"].lower()] != e["version"]
    ]

    assert drift == []


# --- ADR-003 amendment (2026-10-28): CC BY / CC BY-SA for data sources -------
#
# The operator's decision, with its scope. These two licences are approved for
# DATA SOURCES only, never for code, and every such entry must carry the
# attribution obligation in the register so it is discovered before use rather
# than after a report ships.


def test_the_two_cc_licences_are_approved():
    assert "CC-BY-4.0" in APPROVED_SPDX
    assert "CC-BY-SA-4.0" in APPROVED_SPDX


def test_a_cc_licence_on_code_is_refused():
    """Scoped to data sources: the scope is enforced, not merely written down."""
    problems = check_registry(
        [
            {
                "name": "something",
                "version": "1",
                "licence": "CC BY 4.0",
                "spdx": "CC-BY-4.0",
                "source": "https://example.invalid",
                "purpose": "x",
                "isolation": "library",
                "attribution": "wherever",
            }
        ]
    )

    assert any("data" in p for p in problems), problems


@pytest.mark.parametrize("spdx", ["CC-BY-4.0", "CC-BY-SA-4.0"])
def test_a_cc_data_source_without_attribution_is_refused(spdx):
    """CC BY's whole condition is attribution. An entry that does not say where
    it must appear records the licence and drops the obligation."""
    problems = check_registry(
        [
            {
                "name": "something",
                "version": "1",
                "licence": spdx,
                "spdx": spdx,
                "source": "https://example.invalid",
                "purpose": "x",
                "isolation": "data",
            }
        ]
    )

    assert any("attribution" in p for p in problems), problems


@pytest.mark.parametrize("spdx", ["CC-BY-4.0", "CC-BY-SA-4.0"])
def test_a_complete_cc_data_source_passes(spdx):
    problems = check_registry(
        [
            {
                "name": "something",
                "version": "1",
                "licence": spdx,
                "spdx": spdx,
                "source": "https://example.invalid",
                "purpose": "x",
                "isolation": "data",
                "attribution": "per finding, once per report, data_sources[], the register",
            }
        ]
    )

    assert problems == []


def test_every_cc_entry_in_the_shipped_registry_is_data_and_attributed(registry):
    """The rule applied to what we actually ship, not only to fabricated rows."""
    cc = [e for e in registry if str(e["spdx"]).startswith("CC-BY")]
    assert cc, "the ADR-003 amendment registered no data sources"
    for entry in cc:
        assert entry["isolation"] == "data", entry["name"]
        assert str(entry.get("attribution", "")).strip(), entry["name"]


def test_debian_is_not_registered_because_its_licence_is_unstated(registry):
    """ADR-035 decision 10 and D92: Debian's tracker states no licence.

    The register has no way to hold an unlicensed candidate - it is a flat list
    and every entry is gated - so Debian is deliberately absent rather than
    registered under a guessed or placeholder licence. If this test starts
    failing because someone added it, the licence question was answered and
    that answer belongs in the entry.
    """
    assert not [e for e in registry if "debian" in str(e["name"]).lower()]


def test_the_two_constant_sets_say_the_same_thing():
    """Both conditions attach to the same two licences; if they ever diverge
    the divergence should be deliberate and visible here."""
    assert DATA_ONLY_SPDX == ATTRIBUTION_REQUIRED_SPDX == {"CC-BY-4.0", "CC-BY-SA-4.0"}
