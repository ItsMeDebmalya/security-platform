import json

from scanners.web.checks import CHECKS
from scanners.web.fetch import probe_path
from tests.scanners.web.conftest import FakeSite
from tests.scanners.web.test_web_scanner import HARDENED, PAGE, hardened, only, run

PROBE = probe_path("x.test")
NGINX_LISTING = (
    "<title>Index of /assets/</title><h1>Index of /assets/</h1><pre>"
    '<a href="../">../</a><a href="app.js">app.js</a></pre>'
)


def by_id(result, check_id):
    return [f for f in result.findings if f.check_id == check_id]


def test_every_catalogue_check_is_accounted_for(site):
    result = run(hardened(site))
    assert {c.check_id for c in result.telemetry.checks_run} == set(CHECKS)


def test_mixed_content_and_missing_sri_are_suspected(site):
    hardened(site)
    body = (
        '<script src="http://cdn.y.test/legacy.js"></script>'
        '<script src="https://cdn.y.test/lib.js"></script>'
        '<script src="https://cdn.y.test/ok.js" integrity="sha384-x"></script>'
        '<script src="/own.js"></script>'
    )
    site.serve("https://x.test/", headers=HARDENED, body=body)
    result = run(site)
    mixed = only(result, "web-mixed-content")
    assert mixed.state == "suspected" and "http://cdn.y.test/legacy.js" in mixed.description
    sri = only(result, "web-sri-missing")
    assert "https://cdn.y.test/lib.js" in sri.description
    assert "ok.js" not in sri.description and "own.js" not in sri.description


def test_version_disclosure_and_technology(site):
    hardened(site)
    site.serve("https://x.test/", headers={**HARDENED, "server": "nginx/1.27.3"}, body=PAGE)
    result = run(site)
    assert "nginx/1.27.3" in only(result, "web-version-disclosure").description
    tech = only(result, "web-technology")
    assert tech.state == "informational" and "nginx" in tech.description


def test_secret_is_reported_but_never_stored(site):
    hardened(site)
    site.serve(
        "https://x.test/", headers=HARDENED, body='<script>var k = "AKIAIOSFODNN7EXAMPLE";</script>'
    )
    result = run(site)
    f = only(result, "web-secret-in-response")
    assert f.state == "suspected" and "aws_access_key_id" in f.description
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(result.model_dump(mode="json"))


def test_google_browser_key_is_not_a_secret_finding(site):
    hardened(site)
    site.serve(
        "https://x.test/",
        headers=HARDENED,
        body='<script>var m = "AIzaSyD0labPlaceholderNotARealKey000000";</script>',
    )
    assert not by_id(run(site), "web-secret-in-response")


def test_listing_corroborated_by_homepage_link_is_highly_likely(site):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body='<script src="/assets/app.js"></script>')
    site.serve("https://x.test/assets/", headers=HARDENED, body=NGINX_LISTING)
    f = only(run(site), "web-directory-listing")
    assert f.location == "/assets/" and f.state == "highly_likely"


def test_listing_without_corroboration_is_suspected(site):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body='<script src="/assets/other.js"></script>')
    site.serve("https://x.test/assets/", headers=HARDENED, body=NGINX_LISTING)
    assert only(run(site), "web-directory-listing").state == "suspected"


def test_forbidden_directory_is_clear(site):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body='<script src="/assets/app.js"></script>')
    site.serve("https://x.test/assets/", status=403, headers=HARDENED, body="Forbidden")
    result = run(site)
    assert not by_id(result, "web-directory-listing")
    assert any(
        c.check_id == "web-directory-listing" and c.location == "/assets/" and c.outcome == "clear"
        for c in result.telemetry.checks_run
    )


def test_django_debug_page_on_probe(site):
    hardened(site)
    site.serve(
        f"https://x.test{PROBE}",
        status=404,
        headers=HARDENED,
        body="You\u2019re seeing this error because you have <code>DEBUG = True</code>",
    )
    result = run(site)
    f = only(result, "web-debug-mode")
    assert f.state == "suspected" and f.location == PROBE
    assert not by_id(result, "web-error-disclosure")


def test_traceback_on_probe_and_ambiguity_when_on_homepage(site):
    hardened(site)
    trace = '<pre>Traceback (most recent call last):\n  File "/app/s.py", line 9</pre>'
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    assert only(run(site), "web-error-disclosure").state == "suspected"
    other = hardened(FakeSite())
    other.serve("https://x.test/", headers=HARDENED, body=trace)
    other.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    f = only(run(other), "web-error-disclosure")
    assert f.state == "inconclusive" and f.no_verdict_reason == "ambiguous_response"


def test_eol_component_is_suspected_and_capped(site):
    hardened(site)
    site.serve("https://x.test/", headers={**HARDENED, "x-powered-by": "PHP/7.4.33"}, body=PAGE)
    f = only(run(site), "web-component-eol")
    assert f.state == "suspected" and f.confidence <= 0.6
    assert f.instance_key == "PHP:7.4" and f.references and f.references[0].startswith("https://")


def test_supported_component_is_clear(site):
    hardened(site)
    site.serve("https://x.test/", headers={**HARDENED, "x-powered-by": "PHP/8.4.1"}, body=PAGE)
    assert not by_id(run(site), "web-component-eol")


def test_robots_inventory_never_fetches_listed_paths(site):
    hardened(site)
    site.serve(
        "https://x.test/robots.txt",
        headers={"content-type": "text/plain"},
        body="User-agent: *\nDisallow: /admin/\n",
    )
    f = only(run(site), "web-robots-paths")
    assert f.state == "informational" and "/admin/" in f.description
    assert "https://x.test/admin/" not in site.calls


def test_security_txt_missing_and_soft_404(site):
    hardened(site)
    site.serve("https://x.test/.well-known/security.txt", status=404, body="nf")
    assert only(run(site), "web-security-txt-missing").state == "informational"
    other = hardened(FakeSite())
    other.serve("https://x.test/.well-known/security.txt", headers=HARDENED, body=PAGE)
    assert only(run(other), "web-security-txt-missing").state == "informational"


def test_soft_404_site_makes_no_listing_or_error_claims():  # Review Focus 1
    soft = FakeSite(default=(200, HARDENED, '<script src="/static/app.js"></script>'))
    hardened(soft)
    soft.serve(f"https://x.test{PROBE}", headers=HARDENED, body=PAGE)
    result = run(soft)
    assert not [
        f
        for f in result.findings
        if f.check_id in ("web-directory-listing", "web-error-disclosure", "web-debug-mode")
    ]


def test_non_html_root_does_not_crash(site):  # Review Focus 4
    hardened(site)
    site.serve(
        "https://x.test/",
        headers={**HARDENED, "content-type": "application/json"},
        body='{"ok": true}',
    )
    result = run(site)
    assert not by_id(result, "web-mixed-content") and not by_id(result, "web-sri-missing")
