"""Invariants on the live authorisation file.

config/authorised_scope.yaml is not configuration. It is the record produced
if anyone ever asks by what right we touched a system, and the single worst
thing that can happen to this project is a row in it for an asset we do not
control.

docs/09 states that rule in prose. These tests make it a build failure, so it
survives a tired afternoon.
"""

from __future__ import annotations

import ipaddress
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from core.authz import AuthorisedScope
from core.models import Asset

ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / "config" / "authorised_scope.yaml"

RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost")
"""RFC 2606 reserves these. Nobody can register them, so a name under one of
them cannot belong to a third party."""

MAX_AUTHORISATION_DAYS = 90


def rows() -> list[dict]:
    return yaml.safe_load(LIVE.read_text()) or []


def _host(row: dict) -> str:
    value = row["target"]["value"]
    if row["target"]["type"] == "url":
        return urlsplit(value).hostname or value
    return value


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


def _is_local_or_reserved(host: str) -> bool:
    return _is_loopback(host) or host.endswith(RESERVED_TLDS)


def test_the_live_file_loads():
    AuthorisedScope.load(LIVE)


@pytest.mark.parametrize("row", rows(), ids=lambda r: r["authz_id"])
def test_a_self_owned_row_targets_only_loopback_or_a_reserved_name(row):
    """`self_owned` means we started the process. That is credible for our own
    loopback and for an RFC 2606 name that resolves nowhere else; it is not
    credible for a public domain, which needs real proof instead."""
    if row["method"] != "self_owned":
        return

    host = _host(row)
    assert _is_local_or_reserved(host), (
        f"{row['authz_id']} claims self_owned for {host!r}, which is a publicly "
        "resolvable name. Prove control with a dns_txt nonce, or remove the row."
    )


@pytest.mark.parametrize("row", rows(), ids=lambda r: r["authz_id"])
def test_a_publicly_resolvable_row_carries_real_proof(row):
    """A row for a name other people can reach needs verification, not an assertion."""
    host = _host(row)
    if _is_local_or_reserved(host):
        return

    assert row["method"] in ("dns_txt", "http_file", "attestation"), (
        f"{row['authz_id']} targets the public name {host!r} with method "
        f"{row['method']!r}. Public targets require a verification method."
    )
    assert row.get("attestation_ref") or row["proof"].get("evidence_file")


@pytest.mark.parametrize("row", rows(), ids=lambda r: r["authz_id"])
def test_every_row_cites_a_proof_file_that_exists(row):
    """'A row asserting verification without its proof is not verification.'

    core/authz.py checks the field is present; it does not stat the file,
    because a scope file must stay loadable from outside the repo. The
    committed file is held to the stricter rule here instead.
    """
    evidence = row["proof"]["evidence_file"]

    assert (ROOT / evidence).exists(), f"{row['authz_id']} cites {evidence}, which is missing"


@pytest.mark.parametrize("row", rows(), ids=lambda r: r["authz_id"])
def test_no_authorisation_runs_longer_than_ninety_days(row):
    span = (row["expires_at"] - row["verified_at"]).days

    assert 0 < span <= MAX_AUTHORISATION_DAYS, (
        f"{row['authz_id']} runs for {span} days; docs/09 caps it at {MAX_AUTHORISATION_DAYS}"
    )


@pytest.mark.parametrize("row", rows(), ids=lambda r: r["authz_id"])
def test_every_row_names_who_verified_it(row):
    assert row.get("verified_by"), f"{row['authz_id']} has no verified_by"


def test_authz_ids_are_unique():
    ids = [row["authz_id"] for row in rows()]

    assert len(ids) == len(set(ids))


# --- the gate still works ---------------------------------------------------


def test_an_unlisted_target_is_still_denied_standard_mode():
    scope = AuthorisedScope.load(LIVE)

    assert not scope.authorise(Asset(type="domain", value="python.org"), mode="standard").allowed


def test_light_mode_still_needs_no_authorisation():
    scope = AuthorisedScope.load(LIVE)

    assert scope.authorise(Asset(type="domain", value="python.org"), mode="light").allowed


def test_the_local_targets_are_authorised_for_standard_mode():
    scope = AuthorisedScope.load(LIVE)
    today = date(2026, 8, 24)

    for value in ("http://127.0.0.1:3000", "http://127.0.0.1:5000", "http://127.0.0.1:5001"):
        decision = scope.authorise(Asset(type="url", value=value), mode="standard", today=today)
        assert decision.allowed, f"{value}: {decision.reason}"


def test_the_badssl_wildcard_covers_its_subdomains():
    scope = AuthorisedScope.load(LIVE)
    today = date(2026, 8, 24)

    decision = scope.authorise(
        Asset(type="domain", value="expired.badssl.test"), mode="standard", today=today
    )

    assert decision.allowed


def test_the_authorisations_have_not_silently_lapsed():
    """A reminder, not a trap: these expire and must be renewed deliberately."""
    soonest = min(row["expires_at"] for row in rows())

    if soonest < date.today():
        pytest.fail(
            f"the earliest authorisation expired on {soonest}. Re-verify the targets and "
            "update config/authorised_scope.yaml rather than extending the dates."
        )
    if soonest - date.today() < timedelta(days=14):
        pytest.skip(f"authorisations expire on {soonest} - renew them soon")
