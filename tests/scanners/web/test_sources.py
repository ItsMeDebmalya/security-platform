import datetime as dt

import pytest

from scanners.web.sources import Observation, parse_source

D = dt.date(2026, 10, 7)


def _obs(**kw):
    base = {"host": "example.org", "date": D, "seen": "Server: x"}
    base.update(kw)
    return base


def test_vendor_source():
    s = parse_source({"tier": "vendor", "url": "https://a.example/x", "note": "n"})
    assert s.tier == "vendor"
    assert s.url == "https://a.example/x"
    assert s.note == "n"
    assert s.observations == ()
    assert s.reference == "https://a.example/x"


def test_observed_source_with_two_observations():
    s = parse_source(
        {
            "tier": "observed",
            "observations": [_obs(), _obs(host="b.example", seen="X-Powered-By: Y")],
        }
    )
    assert s.tier == "observed"
    assert s.url is None
    assert s.observations[0] == Observation("example.org", D, "Server: x")
    assert s.reference == (
        "observed example.org 2026-10-07: Server: x; observed b.example 2026-10-07: X-Powered-By: Y"
    )


@pytest.mark.parametrize(
    "raw",
    [
        "https://a.example",
        None,
        ["tier"],
        {"url": "https://a.example"},
        {"tier": "blog", "url": "https://a.example"},
        {"tier": "vendor"},
        {"tier": "vendor", "url": "http://a.example"},
        {"tier": "vendor", "url": "https://a.example", "note": 5},
        {"tier": "observed"},
        {"tier": "observed", "observations": []},
        {"tier": "observed", "observations": [{k: v for k, v in _obs().items() if k != "host"}]},
        {"tier": "observed", "observations": [{k: v for k, v in _obs().items() if k != "date"}]},
        {"tier": "observed", "observations": [_obs(date="2026-10-07")]},
        {"tier": "observed", "observations": [{k: v for k, v in _obs().items() if k != "seen"}]},
        {"tier": "observed", "observations": [_obs(seen="")]},
        {"tier": "observed", "observations": [_obs(host="")]},
        {"tier": "observed", "observations": ["x"]},
    ],
)
def test_invalid_sources_raise(raw):
    with pytest.raises(ValueError):
        parse_source(raw)
