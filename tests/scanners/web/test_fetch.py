import pytest

from core.http import MissingFixtureError
from core.killswitch import ScanKilledError
from core.models import Asset
from scanners.web import fetch
from tests.scanners.web.conftest import ConnectTimeout

HTML = {"content-type": "text/html"}
PROBE = fetch.probe_path("x.test")


def gather(site, value="x.test", kind="domain"):
    ctx = site.ctx()
    return fetch.gather(ctx, ctx.http, Asset(type=kind, value=value))


def test_probe_path_is_deterministic_and_host_specific():
    assert fetch.probe_path("x.test") == PROBE and PROBE.startswith("/sp-404-probe-")
    assert fetch.probe_path("y.test") != PROBE


def test_the_plan_for_a_domain(site):
    site.serve("https://x.test/", headers=HTML, body='<script src="/static/app.js"></script>')
    site.serve(
        "https://x.test/robots.txt",
        headers={"content-type": "text/plain"},
        body="Sitemap: https://x.test/sitemap.xml\nSitemap: https://other.test/s.xml\n",
    )
    obs = gather(site)
    assert site.calls == [
        "https://x.test/",
        "http://x.test/",
        f"https://x.test{PROBE}",
        f"http://x.test{PROBE}",
        "https://x.test/robots.txt",
        "https://x.test/sitemap.xml",
        "https://x.test/.well-known/security.txt",
        "https://x.test/static/",
    ]
    assert obs.requests_made == 8 and obs.page is not None


def test_never_more_than_max_requests(site):
    body = "".join(f'<img src="/d{i}/x.png">' for i in range(10))
    robots = "".join(f"Sitemap: https://x.test/s{i}.xml\n" for i in range(5))
    site.serve("https://x.test/", headers=HTML, body=body)
    site.serve("https://x.test/robots.txt", body=robots)
    obs = gather(site)
    assert obs.requests_made <= fetch.MAX_REQUESTS
    assert len(obs.directories) == 4 and len(obs.sitemaps) == 2


def test_transport_failure_is_recorded_not_raised(site):
    site.raise_on("https://x.test/", ConnectTimeout("boom"))
    site.serve("http://x.test/", headers=HTML, body="<p>plain</p>")
    obs = gather(site)
    assert obs.https_root.failure == "timeout" and obs.https_root.response is None
    assert obs.root is obs.http_root
    assert "http://x.test/robots.txt" in site.calls  # falls back to the origin that answered


def test_429_and_challenge(site):
    site.serve("https://x.test/", status=429)
    assert gather(site).https_root.failure == "rate_limited"
    other = type(site)()
    other.serve("https://x.test/", status=403, headers={"cf-mitigated": "challenge"})
    assert gather(other).https_root.failure == "waf_block"


def test_fixture_gap_and_kill_switch_propagate(site):
    site.raise_on("https://x.test/", MissingFixtureError("no fixture"))
    with pytest.raises(MissingFixtureError):
        gather(site)
    other = type(site)()
    ctx = other.ctx()
    ctx.killswitch.kill(scan_id=ctx.scan_id, reason="test")
    with pytest.raises(ScanKilledError):
        fetch.gather(ctx, ctx.http, Asset(type="domain", value="x.test"))


def test_url_with_explicit_port_skips_the_other_scheme(site):
    site.serve("https://x.test:8443/app", headers=HTML, body="<p>app</p>")
    obs = gather(site, "https://x.test:8443/app", "url")
    assert obs.root_path == "/app"
    assert obs.http_root.failure == "blocked_prerequisite" and obs.http_root.response is None
    assert not any(c.startswith("http://") for c in site.calls)


class ConnectError(Exception):
    """Named like httpx's."""


_VERIFY = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
EXPIRED = ConnectError(_VERIFY + "certificate has expired (_ssl.c:1032)")
SELF_SIGNED = ConnectError(_VERIFY + "self-signed certificate (_ssl.c:1032)")
WRONG_HOST = ConnectError(
    _VERIFY + "Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'. "
    "(_ssl.c:1032)"
)
HANDSHAKE = ConnectError(
    "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] ssl/tls alert handshake failure (_ssl.c:1032)"
)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (EXPIRED, "TLS certificate verification failed (certificate has expired)"),
        (SELF_SIGNED, "TLS certificate verification failed (self-signed certificate)"),
        (
            WRONG_HOST,
            "TLS certificate verification failed (Hostname mismatch, certificate is not "
            "valid for 'wrong.host.badssl.com')",
        ),
        (HANDSHAKE, "TLS handshake failed (ssl/tls alert handshake failure)"),
        (ConnectTimeout(""), "connection timed out"),
        (ConnectError("All connection attempts failed: Connection refused"), "connection refused"),
        (ConnectError("[Errno -2] Name or service not known"), "DNS lookup failed"),
        (ConnectError("[Errno -3] Temporary failure in name resolution"), "DNS lookup failed"),
        (ValueError("odd"), "transport error (ValueError)"),
    ],
)
def test_describe_transport_failure(exc, expected):
    assert fetch.describe_transport_failure(exc) == expected


def test_transport_detail_is_redacted_and_capped():
    out = fetch.describe_transport_failure(ValueError("x AKIAIOSFODNN7EXAMPLE y"))
    assert out == "transport error (ValueError)"
    out = fetch.describe_transport_failure(
        ConnectError("[SSL: BAD] key AKIAIOSFODNN7EXAMPLE " + "z" * 500 + " (_ssl.c:1)")
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in out and len(out) <= 200


def test_gather_records_why_https_failed(site):
    site.raise_on("https://x.test/", EXPIRED)
    site.serve("http://x.test/", headers=HTML, body="<p>plain</p>")
    obs = gather(site)
    assert obs.https_root.failure == "blocked_prerequisite"
    assert obs.https_root.detail == "TLS certificate verification failed (certificate has expired)"
