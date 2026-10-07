import json

from scanners.web.checks import CHECKS
from scanners.web.fetch import probe_path
from tests.scanners.web.conftest import ConnectTimeout, FakeSite
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


def test_error_excerpt_never_stores_a_secret():
    site = hardened(FakeSite())
    trace = (
        '<pre>Traceback (most recent call last):\n  File "/app/s.py", line 9\n'
        "key = AKIAIOSFODNN7EXAMPLE</pre>"
    )
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    result = run(site)
    assert by_id(result, "web-error-disclosure")
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(result.model_dump(mode="json"))


def test_token_in_script_url_is_not_stored(site):
    hardened(site)
    token = "ghp_" + "a1B2c3D4e5" * 3
    site.serve(
        "https://x.test/",
        headers=HARDENED,
        body=f'<script src="https://cdn.y.test/a.js?k={token}"></script>',
    )
    result = run(site)
    assert by_id(result, "web-sri-missing")
    assert token not in json.dumps(result.model_dump(mode="json"))


def test_security_txt_5xx_is_inconclusive(site):
    hardened(site)
    site.serve("https://x.test/.well-known/security.txt", status=503, body="down")
    f = only(run(site), "web-security-txt-missing")
    assert f.state == "inconclusive" and f.no_verdict_reason == "ambiguous_response"


def test_robots_5xx_is_inconclusive(site):
    hardened(site)
    site.serve("https://x.test/robots.txt", status=500, body="err")
    assert only(run(site), "web-robots-paths").state == "inconclusive"


def test_directory_5xx_is_inconclusive(site):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body='<script src="/assets/app.js"></script>')
    site.serve("https://x.test/assets/", status=500, headers=HARDENED, body="err")
    f = only(run(site), "web-directory-listing")
    assert f.state == "inconclusive" and f.location == "/assets/"


def test_error_claim_needs_a_usable_root():
    site = hardened(FakeSite())
    trace = '<pre>Traceback (most recent call last):\n  File "/app/s.py", line 9</pre>'
    site.raise_on("https://x.test/", ConnectTimeout("t"))
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    assert only(run(site), "web-error-disclosure").state == "inconclusive"


def test_same_error_on_homepage_clears_debug_check():
    site = hardened(FakeSite())
    trace = '<pre>Traceback (most recent call last):\n  File "/app/s.py", line 9</pre>'
    site.serve("https://x.test/", headers=HARDENED, body=trace)
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    result = run(site)
    assert not by_id(result, "web-debug-mode")
    assert any(
        c.check_id == "web-debug-mode" and c.outcome == "clear" for c in result.telemetry.checks_run
    )


def _dump(result):
    return json.dumps(result.model_dump(mode="json"))


def test_secret_in_server_header_is_not_stored(site):
    hardened(site)
    site.serve(
        "https://x.test/",
        headers={**HARDENED, "server": "nginx/1.27.3 AKIAIOSFODNN7EXAMPLE"},
        body=PAGE,
    )
    result = run(site)
    assert by_id(result, "web-version-disclosure") and by_id(result, "web-technology")
    assert "AKIAIOSFODNN7EXAMPLE" not in _dump(result)


def test_secret_in_powered_by_header_is_not_stored(site):
    hardened(site)
    token = "ghp_" + "a1B2c3D4e5" * 3
    site.serve(
        "https://x.test/", headers={**HARDENED, "x-powered-by": f"PHP/7.4.33 {token}"}, body=PAGE
    )
    result = run(site)
    assert by_id(result, "web-component-eol") and by_id(result, "web-version-disclosure")
    assert token not in _dump(result)


def test_secret_in_csp_header_is_not_stored(site):
    hardened(site)
    token = "ghp_" + "a1B2c3D4e5" * 3
    csp = f"script-src 'unsafe-inline' https://cdn.y.test/{token}/x.js"
    site.serve("https://x.test/", headers={**HARDENED, "content-security-policy": csp}, body=PAGE)
    result = run(site)
    assert by_id(result, "web-csp-weak")
    assert token not in _dump(result)


def test_secret_in_url_path_is_not_stored(site):
    hardened(site)
    key = "AKIAIOSFODNN7EXAMPLE"
    site.serve("https://x.test/", headers=HARDENED, body=f'<script src="/{key}/app.js"></script>')
    site.serve(f"https://x.test/{key}/", headers=HARDENED, body=NGINX_LISTING)
    result = run(site)
    listing = [f for f in by_id(result, "web-directory-listing")]
    assert len(listing) == 1 and listing[0].state == "highly_likely"
    assert key not in _dump(result)


def test_secret_in_header_name_is_not_stored(site):
    hardened(site)
    site.serve(
        "https://x.test/",
        headers={**HARDENED, "server": "nginx/1.27.3", "x-AKIAIOSFODNN7EXAMPLE": "1"},
        body=PAGE,
    )
    result = run(site)
    assert by_id(result, "web-version-disclosure")
    assert "AKIAIOSFODNN7EXAMPLE" not in _dump(result)


# --- Final review C1: a private key's body must never be stored -------------


def _pem_body_lines():
    import base64
    import hashlib

    raw = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(12))
    text = base64.b64encode(raw).decode()
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def _pem():
    lines = _pem_body_lines()
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----"
    )


def _assert_no_key_body(result):
    dumped = _dump(result)
    for line in _pem_body_lines():
        assert line not in dumped and line[-24:] not in dumped, line
    assert "END RSA PRIVATE KEY" not in dumped


def test_private_key_on_homepage_is_reported_and_its_body_never_stored(site):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body=f"<pre>{_pem()}</pre>")
    result = run(site)
    f = only(result, "web-secret-in-response")
    assert "private_key" in f.description
    assert "private_key" in f.evidence[0].redactions  # core still records the hit
    _assert_no_key_body(result)


def test_private_key_in_error_page_excerpt_is_never_stored(site):
    hardened(site)
    # The key sits just before the trace, so the excerpt window (80 chars either
    # side of the signature) starts mid-key: its BEGIN line is outside the window.
    trace = f'<pre>{_pem()}\nTraceback (most recent call last):\n  File "/app/s.py", line 9\n</pre>'
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    result = run(site)
    assert by_id(result, "web-error-disclosure")
    assert any(f.location == PROBE for f in by_id(result, "web-secret-in-response"))
    _assert_no_key_body(result)


def test_unterminated_private_key_is_stripped_to_the_end():
    from core.evidence import redact_body
    from scanners.web.scanner import _redacted, _strip_private_keys

    body = "a -----BEGIN PRIVATE KEY-----\nMIIabc\nMIIdef"
    stripped = _strip_private_keys(body)
    assert "MIIabc" not in stripped and "MIIdef" not in stripped
    assert redact_body(stripped) == ("a [redacted]:private_key", ["private_key"])
    assert _redacted(body) == "a [redacted]:private_key"
    two = (
        "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\nkeep\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n-----END OPENSSH PRIVATE KEY-----"
    )
    assert _redacted(two) == "[redacted]:private_key\nkeep\n[redacted]:private_key"


# --- Minor 11: the robots description is bounded ----------------------------


def test_robots_description_caps_listed_paths(site):
    hardened(site)
    rules = "".join(f"Disallow: /p{i}/\n" for i in range(50))
    site.serve("https://x.test/robots.txt", headers={"content-type": "text/plain"}, body=rules)
    f = only(run(site), "web-robots-paths")
    assert "/p19/" in f.description and "/p20/" not in f.description
    assert "and 30 more" in f.description
    assert len(f.description) <= 2000
