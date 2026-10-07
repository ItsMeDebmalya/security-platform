import pytest

from core.http import MissingFixtureError
from core.killswitch import ScanKilledError
from core.models import Asset
from scanners.web.fetch import probe_path
from tests.scanners.web.conftest import ConnectTimeout, FakeSite

PROBE = probe_path("x.test")
PAGE = "<!doctype html><html><head><title>t</title></head><body><p>hi</p></body></html>"
HARDENED = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def hardened(site):
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve("http://x.test/", status=301, headers={"location": "https://x.test/"})
    site.serve(f"https://x.test{PROBE}", status=404, headers=HARDENED, body="<h1>Not Found</h1>")
    site.serve(f"http://x.test{PROBE}", status=301, headers={"location": f"https://x.test{PROBE}"})
    site.serve(
        "https://x.test/.well-known/security.txt",
        headers={"content-type": "text/plain"},
        body="Contact: mailto:security@x.test\nExpires: 2027-01-01T00:00:00Z\n",
    )
    return site


def bare(site):
    site.serve("https://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve("http://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    return site


def run(site, value="x.test", kind="domain"):
    from scanners.web import WebScanner

    return WebScanner().run(Asset(type=kind, value=value), "light", site.ctx())


def only(result, check_id):
    found = [f for f in result.findings if f.check_id == check_id]
    assert len(found) == 1, (check_id, [f.state for f in found])
    return found[0]


def claims(result):
    return {
        (f.check_id, f.location)
        for f in result.findings
        if f.state in ("confirmed", "highly_likely")
    }


def test_hardened_site_reports_nothing_but_informational(site):
    result = run(hardened(site))
    assert [f.check_id for f in result.findings if f.state != "informational"] == []


def test_bare_site_header_claims_are_confirmed(site):
    result = run(bare(site))
    assert claims(result) >= {
        ("web-https-redirect-missing", "/"),
        ("web-hsts-missing", "/"),
        ("web-csp-missing", "/"),
        ("web-clickjacking-unprotected", "/"),
        ("web-xcto-missing", "/"),
    }
    for f in result.findings:
        if f.state == "confirmed":
            assert f.validation.outcome == "passed"
            assert f.validation.method == "second_same_origin_response"


def test_header_set_per_route_is_only_suspected(site):
    hardened(site)
    no_hsts = {k: v for k, v in HARDENED.items() if k != "strict-transport-security"}
    site.serve("https://x.test/", headers=no_hsts, body=PAGE)
    f = only(run(site), "web-hsts-missing")
    assert f.state == "suspected" and f.validation.outcome == "failed"


def test_weak_hsts_and_weak_csp(site):
    hardened(site)
    weak = {
        **HARDENED,
        "strict-transport-security": "max-age=300",
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; "
        "frame-ancestors 'none'",
    }
    site.serve("https://x.test/", headers=weak, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=404, headers=weak, body="nf")
    result = run(site)
    assert {("web-hsts-weak", "/"), ("web-csp-weak", "/")} <= claims(result)
    assert not [f for f in result.findings if f.check_id == "web-hsts-missing"]


def test_meta_csp_counts_as_a_policy(site):
    hardened(site)
    no_csp = {k: v for k, v in HARDENED.items() if k != "content-security-policy"}
    body = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
    site.serve("https://x.test/", headers=no_csp, body=body + "</head></html>")
    assert not [f for f in run(site).findings if f.check_id == "web-csp-missing"]


def test_duplicate_header_values_do_not_false_positive(site):  # Review Focus 3
    hardened(site)
    dup = {
        **HARDENED,
        "x-frame-options": "DENY, DENY",
        "x-content-type-options": "nosniff, nosniff",
    }
    site.serve("https://x.test/", headers=dup, body=PAGE)
    ids = {f.check_id for f in run(site).findings}
    assert "web-clickjacking-unprotected" not in ids and "web-xcto-missing" not in ids


def test_referrer_and_cors(site):
    hardened(site)
    h = {**HARDENED, "referrer-policy": "unsafe-url", "access-control-allow-origin": "*"}
    site.serve("https://x.test/", headers=h, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=404, headers=h, body="nf")
    assert {("web-referrer-policy-unsafe", "/"), ("web-cors-wildcard", "/")} <= claims(run(site))


def test_missing_referrer_policy_is_informational(site):
    result = run(bare(site))
    assert only(result, "web-referrer-policy-missing").state == "informational"


def test_challenge_makes_header_checks_inconclusive(site):
    site.serve(
        "https://x.test/",
        status=403,
        headers={"cf-mitigated": "challenge", "content-type": "text/html"},
        body="<title>Just a moment...</title>",
    )
    result = run(site)
    for cid in ("web-hsts-missing", "web-csp-missing", "web-xcto-missing"):
        f = only(result, cid)
        assert f.state == "inconclusive" and f.no_verdict_reason == "waf_block"


def test_https_unreachable_blocks_only_https_checks(site):
    site.raise_on("https://x.test/", ConnectTimeout("t"))
    site.raise_on(f"https://x.test{PROBE}", ConnectTimeout("t"))
    site.serve("http://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    result = run(site)
    assert only(result, "web-hsts-missing").no_verdict_reason == "timeout"
    assert only(result, "web-https-redirect-missing").state == "inconclusive"
    assert only(result, "web-xcto-missing").state == "confirmed"  # judged on the HTTP root


def test_rate_limited_and_server_error_roots(site):
    site.serve("https://x.test/", status=429)
    assert only(run(site), "web-hsts-missing").no_verdict_reason == "rate_limited"
    other = FakeSite()
    other.serve("https://x.test/", status=503, body="down")
    assert only(run(other), "web-xcto-missing").no_verdict_reason == "ambiguous_response"


def test_cdn_is_named_in_header_findings(site):
    bare(site)
    site.serve(
        "https://x.test/", headers={"content-type": "text/html", "cf-ray": "abc-BOM"}, body=PAGE
    )
    assert "Cloudflare" in only(run(site), "web-hsts-missing").description


def test_redirect_to_www_stays_in_scope(site):  # Review Focus 2
    site.serve("https://x.test/", status=301, headers={"location": "https://www.x.test/"})
    site.serve("http://x.test/", status=301, headers={"location": "https://www.x.test/"})
    site.serve(
        "https://www.x.test/", headers=HARDENED, body='<script src="/static/app.js"></script>'
    )
    result = run(site)
    assert "https://www.x.test/static/" in site.calls
    assert all(".x.test" in c or "//x.test" in c for c in site.calls)
    assert not [
        f
        for f in result.findings
        if f.check_id == "web-https-redirect-missing" and f.state != "inconclusive"
    ]


def test_url_target_with_explicit_port(site):
    site.serve("https://x.test:8443/", headers=HARDENED, body=PAGE)
    result = run(site, "https://x.test:8443/", "url")
    assert only(result, "web-https-redirect-missing").no_verdict_reason == "blocked_prerequisite"
    assert not any(c.startswith("http://") for c in site.calls)


def test_fixture_gap_and_kill_switch_propagate(site):
    site.raise_on("https://x.test/", MissingFixtureError("gap"))
    with pytest.raises(MissingFixtureError):
        run(site)
    other = FakeSite()
    ctx = other.ctx()
    ctx.killswitch.kill(scan_id=ctx.scan_id, reason="t")
    from scanners.web import WebScanner

    with pytest.raises(ScanKilledError):
        WebScanner().run(Asset(type="domain", value="x.test"), "light", ctx)


def test_every_finding_has_a_control_and_requests_stay_bounded(site):
    result = run(bare(site))
    assert result.findings
    for f in result.findings:
        assert f.evidence and f.evidence[0].has_control()
    assert len(site.calls) <= 12
    assert all("x.test" in c for c in site.calls)


def test_requires_no_authorisation():
    from scanners.web import WebScanner

    for mode in ("light", "standard", "deep"):
        assert WebScanner().requires_authorisation(mode) is False


def _plain(site, **kw):
    site.serve("http://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    return site


def test_5xx_http_probe_does_not_validate_redirect(site):
    _plain(site)
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve(f"http://x.test{PROBE}", status=503, body="down")
    f = only(run(site), "web-https-redirect-missing")
    assert f.state == "suspected" and f.validation.outcome == "unavailable"


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        (
            {
                "status": 403,
                "headers": {"cf-mitigated": "challenge"},
                "body": "<title>Just a moment...</title>",
            },
            "waf_block",
        ),
        ({"status": 429}, "rate_limited"),
        ({"status": 503, "body": "down"}, "ambiguous_response"),
    ],
)
def test_unusable_https_control_makes_redirect_inconclusive(site, kw, reason):
    _plain(site)
    site.serve("https://x.test/", **kw)
    f = only(run(site), "web-https-redirect-missing")
    assert f.state == "inconclusive" and f.no_verdict_reason == reason
    assert "HTTPS is served" not in f.description


def test_https_to_http_downgrade_blocks_hsts_and_redirect(site):
    _plain(site)
    site.serve("https://x.test/", status=301, headers={"location": "http://x.test/"})
    result = run(site)
    for cid in ("web-hsts-missing", "web-hsts-weak", "web-https-redirect-missing"):
        f = only(result, cid)
        assert f.state == "inconclusive" and f.no_verdict_reason == "blocked_prerequisite"


def test_5xx_plain_http_root_is_inconclusive(site):
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve("http://x.test/", status=503, body="down")
    f = only(run(site), "web-https-redirect-missing")
    assert f.state == "inconclusive" and f.no_verdict_reason == "ambiguous_response"


def test_validation_wording_and_control_is_the_probe(site):
    result = run(bare(site))
    f = only(result, "web-xcto-missing")
    assert "origin-wide" in f.description
    assert f.evidence[0].control.request.url == f"https://x.test{PROBE}"
    assert "None" not in f.description
    hardened(site)
    no_hsts = {k: v for k, v in HARDENED.items() if k != "strict-transport-security"}
    site.serve("https://x.test/", headers=no_hsts, body=PAGE)
    assert "per route" in only(run(site), "web-hsts-missing").description


def test_weak_hsts_with_missing_probe_fails_validation(site):
    hardened(site)
    site.serve(
        "https://x.test/",
        headers={**HARDENED, "strict-transport-security": "max-age=300"},
        body=PAGE,
    )
    f = only(run(site), "web-hsts-weak")
    assert f.validation.outcome == "failed"


def test_csp_weak_quotes_received_header(site):
    hardened(site)
    weak = {
        **HARDENED,
        "content-security-policy": (
            "default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'"
        ),
    }
    site.serve("https://x.test/", headers=weak, body=PAGE)
    assert "script-src 'unsafe-inline'" in only(run(site), "web-csp-weak").description


def test_downgraded_https_probe_never_validates_hsts(site):
    hardened(site)
    no_hsts = {k: v for k, v in HARDENED.items() if k != "strict-transport-security"}
    site.serve("https://x.test/", headers=no_hsts, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=301, headers={"location": f"http://x.test{PROBE}"})
    site.serve(f"http://x.test{PROBE}", status=404, body="nf")
    f = only(run(site), "web-hsts-missing")
    assert f.state == "suspected" and f.validation.outcome == "unavailable"


def test_redirect_failed_validation_has_redirect_wording(site):
    _plain(site)
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve(f"http://x.test{PROBE}", status=301, headers={"location": f"https://x.test{PROBE}"})
    f = only(run(site), "web-https-redirect-missing")
    assert f.validation.outcome == "failed"
    assert "specific to this path" in f.description and "header" not in f.description


def test_downgraded_root_note_on_header_findings(site):
    _plain(site)
    site.serve("https://x.test/", status=301, headers={"location": "http://x.test/"})
    f = only(run(site), "web-xcto-missing")
    assert "redirected to plain HTTP" in f.description


def _not_confirmed(f):
    assert f.state != "confirmed" and f.validation.outcome == "unavailable", (f.check_id, f.state)


def test_scheme_downgraded_probe_never_validates_headers(site):  # (a)
    hardened(site)
    no_xcto = {k: v for k, v in HARDENED.items() if k != "x-content-type-options"}
    site.serve("https://x.test/", headers=no_xcto, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=301, headers={"location": f"http://x.test{PROBE}"})
    site.serve(f"http://x.test{PROBE}", status=404, body="nf")
    _not_confirmed(only(run(site), "web-xcto-missing"))


def test_downgraded_root_with_https_probe_is_not_validated(site):  # (b)
    site.serve("https://x.test/", status=301, headers={"location": "http://x.test/"})
    site.serve("http://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=404, body="nf")
    result = run(site)
    _not_confirmed(only(result, "web-xcto-missing"))
    _not_confirmed(only(result, "web-csp-missing"))


def test_control_that_is_the_root_is_not_validated(site):  # (c1)
    hardened(site)
    site.serve("https://x.test/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": "https://x.test/"})
    result = run(site)
    _not_confirmed(only(result, "web-hsts-missing"))
    _not_confirmed(only(result, "web-xcto-missing"))


def test_http_probe_redirecting_to_root_does_not_validate_redirect(site):  # (c2)
    _plain(site)
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve(f"http://x.test{PROBE}", status=302, headers={"location": "http://x.test/"})
    _not_confirmed(only(run(site), "web-https-redirect-missing"))


# --- Fix Round 4: the control must be a distinct, same-origin response -------

FIVE = (
    "web-https-redirect-missing",
    "web-hsts-missing",
    "web-csp-missing",
    "web-clickjacking-unprotected",
    "web-xcto-missing",
)


def _none_of_five_confirmed(result):
    for cid in FIVE:
        _not_confirmed(only(result, cid))


@pytest.mark.parametrize("location", ["https://x.test", "http://x.test", "https://x.test/#a"])
def test_probe_redirecting_to_the_root_in_disguise_is_not_validated(site, location):
    bare(site)
    plain = location.replace("https://", "http://")  # the http probe stays on plain HTTP
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": location})
    site.serve(f"http://x.test{PROBE}", status=302, headers={"location": plain})
    _none_of_five_confirmed(run(site))


@pytest.mark.parametrize(
    "location",
    ["https://x.test/./", "https://X.TEST./", "https://x.test:443/", "/%2e/", "https://x.test//"],
)
def test_probe_redirecting_to_a_normalised_root_is_not_validated(site, location):
    bare(site)
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": location})
    site.serve(f"http://x.test{PROBE}", status=302, headers={"location": "http://x.test/"})
    result = run(site)
    for cid in FIVE[1:]:
        _not_confirmed(only(result, cid))


def test_https_probe_redirecting_to_another_host_is_not_validated(site):  # (h)
    bare(site)
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": "https://www.x.test/"})
    site.serve(f"http://x.test{PROBE}", status=302, headers={"location": "http://www.x.test/"})
    site.serve("https://www.x.test/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve("http://www.x.test/", headers={"content-type": "text/html"}, body=PAGE)
    _none_of_five_confirmed(run(site))


def test_root_on_another_host_than_the_probe_is_not_validated(site):  # (f)
    site.serve("https://x.test/", status=301, headers={"location": "https://www.x.test/"})
    site.serve("https://www.x.test/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve("http://x.test/", status=301, headers={"location": "http://www.x.test/"})
    site.serve("http://www.x.test/", headers={"content-type": "text/html"}, body=PAGE)
    _none_of_five_confirmed(run(site))


def test_http_root_on_another_host_does_not_validate_redirect(site):  # (k)
    site.serve("https://x.test/", headers=HARDENED, body=PAGE)
    site.serve("http://x.test/", status=301, headers={"location": "http://www.x.test/"})
    site.serve("http://www.x.test/", headers={"content-type": "text/html"}, body=PAGE)
    _not_confirmed(only(run(site), "web-https-redirect-missing"))


def test_probe_on_another_port_is_not_validated(site):
    site.serve("https://x.test:8443/", headers={"content-type": "text/html"}, body=PAGE)
    site.serve(
        f"https://x.test:8443{PROBE}", status=302, headers={"location": f"https://x.test{PROBE}"}
    )
    result = run(site, "https://x.test:8443/", "url")
    for cid in FIVE[1:]:
        _not_confirmed(only(result, cid))


def test_probe_redirecting_to_a_distinct_same_origin_page_still_confirms(site):
    bare(site)
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": "https://x.test/login"})
    site.serve("https://x.test/login", status=404, headers={"content-type": "text/html"}, body="nf")
    site.serve(f"http://x.test{PROBE}", status=302, headers={"location": "http://x.test/login"})
    site.serve("http://x.test/login", status=404, headers={"content-type": "text/html"}, body="nf")
    result = run(site)
    for cid in FIVE:
        f = only(result, cid)
        assert f.state == "confirmed" and f.validation.outcome == "passed", (cid, f.state)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://x.test", "https://x.test:443/"),
        ("http://x.test/", "http://x.test:80"),
        ("https://x.test/#a", "https://x.test/"),
        ("HTTPS://X.Test/p", "https://x.test/p"),
        ("https://x.test./", "https://x.test/"),
        ("https://x.test/./a/../", "https://x.test/"),
        ("https://x.test/%2e/", "https://x.test/"),
        ("https://x.test//", "https://x.test/"),
    ],
)
def test_normalised_equal(a, b):
    from scanners.web.scanner import _normalised

    assert _normalised(a) is not None and _normalised(a) == _normalised(b)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://x.test/", "http://x.test/"),
        ("https://x.test/", "https://x.test:8443/"),
        ("https://x.test/", "https://www.x.test/"),
        ("https://x.test/a", "https://x.test/A"),
        ("https://x.test/?q=1", "https://x.test/"),
    ],
)
def test_normalised_differs(a, b):
    from scanners.web.scanner import _normalised

    assert _normalised(a) != _normalised(b)


def test_normalised_shape_and_bad_input():
    from scanners.web.scanner import _normalised

    assert _normalised("https://x.test") == ("https", "x.test", 443, "/", "")
    assert _normalised("http://X.test.:8080/a?b=1#c") == ("http", "x.test", 8080, "/a", "b=1")
    assert _normalised("https://x.test:99999/") is None
    assert _normalised("https://[::1/") is None


@pytest.mark.parametrize(
    "location",
    ["https://x.test/?from=probe", "https://x.test/index.html", "https://x.test/INDEX.PHP"],
)
def test_probe_bounced_to_the_root_resource_is_not_validated(site, location):
    bare(site)
    site.serve(f"https://x.test{PROBE}", status=302, headers={"location": location})
    site.serve(location, headers={"content-type": "text/html"}, body=PAGE)
    result = run(site)
    for cid in FIVE[1:]:
        _not_confirmed(only(result, cid))


def test_normalised_index_document_is_its_directory():
    from scanners.web.scanner import _normalised

    assert _normalised("https://x.test/a/index.htm") == _normalised("https://x.test/a/")
    assert _normalised("https://x.test/index.html.bak") != _normalised("https://x.test/")
