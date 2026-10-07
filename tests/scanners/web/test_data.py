import datetime as dt

import yaml

from core.deprecation_calendar import STALE_AFTER_DAYS
from scanners.web import eol, fingerprint
from scanners.web.sources import parse_source


def _raw(path):
    return yaml.safe_load(path.read_text())


def test_every_entry_has_a_tiered_source():
    for path in (fingerprint.DATA, eol.DATA):
        for entry in _raw(path):
            source = parse_source(entry["source"])
            assert isinstance(entry["reviewed_on"], dt.date)
            for obs in source.observations:
                assert obs.date <= entry["reviewed_on"], (path.name, entry["source"])


def test_eol_sources_are_vendor_tier():
    for entry in _raw(eol.DATA):
        assert parse_source(entry["source"]).tier == "vendor", entry


def test_nothing_from_wappalyzer():  # ADR-003 / SPEC A1 guardrail
    for path in (fingerprint.DATA, eol.DATA):
        assert "wappalyzer" not in path.read_text().lower()


def test_data_is_fresh():
    today = dt.date.today()
    for path in (fingerprint.DATA, eol.DATA):
        for entry in _raw(path):
            age = (today - entry["reviewed_on"]).days
            assert age <= STALE_AFTER_DAYS, f"{path.name}: re-review {entry} ({age} days old)"


def test_eol_entries_are_past_only():
    for entry in eol.load():
        assert entry.eol_date <= entry.reviewed_on, entry


def test_eol_branches_are_quoted_strings():
    for entry in _raw(eol.DATA):
        assert isinstance(entry["branch"], str), entry


def test_eol_products_are_fingerprinted():
    names = {fp.name for fp in fingerprint.load()}
    for entry in eol.load():
        assert entry.product in names, entry.product
