import json

import pytest

from core.models import Asset
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


# --- Minor 11: the robots description is bounded ----------------------------


def test_robots_description_caps_listed_paths(site):
    hardened(site)
    rules = "".join(f"Disallow: /p{i}/\n" for i in range(50))
    site.serve("https://x.test/robots.txt", headers={"content-type": "text/plain"}, body=rules)
    f = only(run(site), "web-robots-paths")
    assert "/p19/" in f.description and "/p20/" not in f.description
    assert "and 30 more" in f.description
    assert len(f.description) <= 2000


# --- Leak fix (v1.0.3): the record-then-replay path, and redact-then-cut ------

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _record_then_replay(site, tmp_path, *, legacy=False, **client_kwargs):
    """Scan live through core's RecordingHttpBackend, then again from the fixtures it
    wrote through ReplayHttpBackend - the corpus / `--replay` path, not FakeSite alone.

    `legacy=True` rewrites every fixture, between the two scans, into what core wrote
    *before* ADR-028 (BEGIN line replaced, key body kept, then truncated). Core no
    longer writes such fixtures, but old recordings exist, so replaying them must
    still store no key (D21)."""
    from core.authz import Scope
    from core.context import ScanContext
    from core.http import HttpClient, RecordingHttpBackend, ReplayHttpBackend
    from scanners.web import WebScanner

    scope = Scope(frozenset({site.host}))
    target = Asset(type="domain", value=site.host)
    results = []
    for backend in (RecordingHttpBackend(tmp_path, site), ReplayHttpBackend(tmp_path)):
        if legacy and isinstance(backend, ReplayHttpBackend):
            _rewrite_as_legacy(site, tmp_path, client_kwargs.get("body_cap"))
        http = HttpClient(scope=scope, backend=backend, **client_kwargs)
        results.append(WebScanner().run(target, "light", ScanContext(http=http, scope=scope)))
    return results


def _rewrite_as_legacy(site, directory, body_cap):
    from core.evidence import DEFAULT_BODY_CAP
    from tests.core.test_redaction_harness import _old_core_capture

    cap = body_cap or DEFAULT_BODY_CAP
    for path in directory.rglob("*.json"):
        data = json.loads(path.read_text())
        raw = site.responses.get(data["url"], site.default)[2]
        data["body"] = _old_core_capture(raw, cap)
        data["body_truncated"] = len(raw) > cap
        path.write_text(json.dumps(data))


def test_private_key_body_is_never_stored_on_record_or_replay(site, tmp_path):
    hardened(site)
    site.serve("https://x.test/", headers=HARDENED, body=f"<pre>{_pem()}</pre>")
    for result in _record_then_replay(site, tmp_path):
        assert only(result, "web-secret-in-response").location == "/"
        _assert_no_key_body(result)


def test_private_key_in_error_excerpt_is_never_stored_on_replay(site, tmp_path):
    hardened(site)
    trace = f'<pre>{_pem()}\nTraceback (most recent call last):\n  File "/app/s.py", line 9\n</pre>'
    site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
    for result in _record_then_replay(site, tmp_path):
        assert "Traceback" in only(result, "web-error-disclosure").description
        assert any(f.location == PROBE for f in by_id(result, "web-secret-in-response"))
        _assert_no_key_body(result)


def test_text_after_a_key_end_line_is_kept_on_record_and_replay(site, tmp_path):
    hardened(site)
    body = f"<pre>{_pem()}</pre><p>Keep this sentence after the key.</p>"
    site.serve("https://x.test/", headers=HARDENED, body=body)
    for result in _record_then_replay(site, tmp_path):
        f = only(result, "web-secret-in-response")
        assert "Keep this sentence after the key." in f.evidence[0].test.response.body
        _assert_no_key_body(result)


def test_key_straddling_core_truncation_is_never_stored_on_replay(site, tmp_path):
    # core truncates the fixture body (after redacting only the BEGIN line), so on
    # replay the gap can swallow BEGIN and leave the key's tail and END line headless.
    hardened(site)
    body = "x" * 1000 + "\n" + _pem() + "\n" + "y" * 40
    site.serve("https://x.test/", headers=HARDENED, body=body)
    live, replayed = _record_then_replay(site, tmp_path, legacy=True, body_cap=400)
    # precondition: the legacy fixture really is headless - key tail and END, no anchor
    bodies = " ".join(b or "" for b in _fixture_bodies(tmp_path))
    assert "END RSA PRIVATE KEY" in bodies and "private_key" not in bodies
    for result in (live, replayed):
        assert only(result, "web-secret-in-response").location == "/"
        _assert_no_key_body(result)


def _fixture_bodies(directory):
    return [json.loads(p.read_text()).get("body") for p in directory.rglob("*.json")]


def _robots_straddle_body():
    return (
        f"Disallow: /{'a' * 1893}\nDisallow: /{AWS_KEY}\nSitemap: https://x.test/{'s' * 400}.xml\n"
    )


def _assert_no_key_prefix(result, key=AWS_KEY):
    dumped = _dump(result)
    assert key not in dumped
    for n in range(8, len(key)):
        assert key[:n] not in dumped, key[:n]


def test_robots_description_redacts_before_capping(site, tmp_path):
    from scanners.web.scanner import DESCRIPTION_CAP

    hardened(site)
    site.serve(
        "https://x.test/robots.txt",
        headers={"content-type": "text/plain"},
        body=_robots_straddle_body(),
    )
    for result in _record_then_replay(site, tmp_path):
        f = only(result, "web-robots-paths")
        assert "(truncated)" in f.description
        assert len(f.description) <= DESCRIPTION_CAP
        _assert_no_key_prefix(result)


def test_capped_is_a_true_ceiling_and_never_splits_a_secret():
    from scanners.web.scanner import _capped

    for pad in range(0, 40):
        text = "p" * (100 + pad) + " " + AWS_KEY + " " + "q" * 200
        out = _capped(text, 130)
        assert len(out) <= 130
        assert not any(AWS_KEY[:n] in out for n in range(8, 21)), (pad, out)
    assert _capped("short", 130) == "short"


def test_error_excerpt_window_never_cuts_a_secret(site):
    # The window ends 80 chars after the signature; put a key across that edge.
    hardened(site)
    sig = "Traceback (most recent call last):"
    for pad in (60, 65, 70, 75):
        trace = f"<pre>{sig}{'z' * pad} {AWS_KEY} tail</pre>"
        site.serve(f"https://x.test{PROBE}", status=500, headers=HARDENED, body=trace)
        result = run(site)
        assert by_id(result, "web-error-disclosure")
        _assert_no_key_prefix(result)


# --- Fix round 2: a key body that lost BOTH anchors to core's truncation ------


def _long_key_lines(n=125):
    import base64
    import hashlib

    raw = b"".join(hashlib.sha256(i.to_bytes(2, "big")).digest() for i in range(n * 2))
    text = base64.b64encode(raw).decode()[: n * 64 - 20]  # last line short, like a real key
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def test_key_body_with_no_surviving_anchor_is_never_stored_on_replay(site, tmp_path):
    # An unterminated key whose BEGIN falls inside core's truncation gap (default
    # 256 KB cap): the fixture keeps only bare key lines - no BEGIN, no END, no marker.
    from core.evidence import DEFAULT_BODY_CAP

    hardened(site)
    lines = _long_key_lines()
    filler = "<p>ordinary words in a paragraph</p>\n"
    head = filler * (131_500 // len(filler))
    key = "<pre>-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n</pre>\n"
    tail = filler * ((DEFAULT_BODY_CAP + 2_000 - len(head) - len(key)) // len(filler) + 1)
    body = head + key + tail
    assert len(body) > DEFAULT_BODY_CAP
    site.serve("https://x.test/", headers=HARDENED, body=body)
    live, replayed = _record_then_replay(site, tmp_path, legacy=True)
    fixture = " ".join(b or "" for b in _fixture_bodies(tmp_path))
    # precondition: the legacy fixture is real - key lines survive, every anchor is gone
    assert lines[-10] in fixture
    assert "BEGIN" not in fixture and "PRIVATE KEY" not in fixture and "private_key" not in fixture
    for result in (live, replayed):
        assert only(result, "web-secret-in-response").location == "/"
        dumped = _dump(result)
        for line in lines:
            assert line not in dumped and line[-24:] not in dumped, line
        assert "ordinary words in a paragraph" in dumped  # the page text survives


# --- Fix round 3: unterminated keys cut to the end; HTML/JSON-escaped separators --


def _key_lines(n=30, width=64, seed=0):
    import base64
    import hashlib

    raw = b"".join(
        hashlib.sha256(bytes([seed]) + i.to_bytes(2, "big")).digest() for i in range(n * 2)
    )
    text = base64.b64encode(raw).decode()[: n * width - 20]
    return [text[i : i + width] for i in range(0, len(text), width)]


def _pem_with(lines, sep="\n", end=True, label="RSA PRIVATE KEY"):
    text = f"-----BEGIN {label}-----" + sep + sep.join(lines)
    return text + (sep + f"-----END {label}-----" if end else "")


def _php_json(obj):
    return json.dumps(obj).replace("/", "\\/")  # PHP json_encode escapes "/"


def _assert_no_lines(result, lines):
    dumped = _dump(result)
    leaked = [line for line in lines if line in dumped or line[-24:] in dumped]
    assert not leaked, f"{len(leaked)}/{len(lines)} key lines stored"
    assert "PRIVATE KEY-----" not in dumped


def _scan_both(tmp_path, body, *, path="/", status=200, legacy=False, **client_kwargs):
    site = hardened(FakeSite())
    site.serve(f"https://x.test{path}", status=status, headers=HARDENED, body=body)
    return _record_then_replay(site, tmp_path, legacy=legacy, **client_kwargs)


KEY = _key_lines()
KEY_PHP = [line.replace("/", "\\/") for line in KEY]
HALF = 262_144 // 2


@pytest.mark.parametrize(
    ("body", "lines"),
    [
        pytest.param(
            "<pre>" + _pem_with(KEY, "<br>\n", end=False) + "</pre><p>x</p>", KEY, id="br"
        ),
        pytest.param(
            '<input value="' + _pem_with(KEY, "&#10;", end=False) + '">', KEY, id="attr-entity"
        ),
        pytest.param(_php_json({"k": _pem_with(KEY, "\n", end=False)}), KEY_PHP, id="php-json"),
        pytest.param(
            "<pre>" + _pem_with(KEY, "<BR />", end=False) + "</pre>", KEY, id="br-upper-slash"
        ),
        pytest.param(
            "<p>" + _pem_with(KEY, "&#xD;&#xA;", end=False) + "</p>", KEY, id="hex-entity"
        ),
    ],
)
def test_unterminated_key_in_any_encoding_is_never_stored(tmp_path, body, lines):
    for result in _scan_both(tmp_path, body):
        assert only(result, "web-secret-in-response").location == "/"
        _assert_no_lines(result, lines)


def test_unterminated_br_key_on_the_404_page_is_never_stored(tmp_path):
    trace = (
        f"<pre>{_pem_with(KEY, '<br>', end=False)}\nTraceback (most recent call last):\n"
        '  File "/app/s.py", line 9\n</pre>'
    )
    live, replayed = _scan_both(tmp_path, trace, path=PROBE, status=500)
    # Live, the check reads the raw page, so the traceback after the key is seen.
    assert by_id(live, "web-error-disclosure")
    # On replay it is not: core cuts an unterminated key to the end of the text in
    # the fixture too (ADR-028: a key has no safe partial boundary), so the
    # traceback is not in what replay serves. The secret is still reported.
    assert not by_id(replayed, "web-error-disclosure")
    assert any(f.location == PROBE for f in by_id(replayed, "web-secret-in-response"))
    for result in (live, replayed):
        _assert_no_lines(result, KEY)


@pytest.mark.parametrize("pad", [HALF - 1000, HALF - 500, HALF - 200])
@pytest.mark.parametrize("encoding", ["br", "php-json"])
def test_terminated_key_straddling_the_default_cap_gap_is_never_stored(tmp_path, pad, encoding):
    if encoding == "br":
        body = "x" * pad + "<pre>" + _pem_with(KEY, "<br>\n") + "</pre>" + "y" * 262_144
        lines = KEY
    else:
        body = _php_json({"pad": "x" * pad, "k": _pem_with(KEY) + "\n", "z": "y" * 262_144})
        lines = KEY_PHP
    for result in _scan_both(tmp_path, body):
        _assert_no_lines(result, lines)


@pytest.mark.parametrize("cap", [400, 1000])
@pytest.mark.parametrize("encoding", ["br", "php-json", "crlf"])
def test_terminated_key_straddling_a_small_gap_is_never_stored(tmp_path, cap, encoding):
    if encoding == "br":
        body, lines = "x" * 900 + "<pre>" + _pem_with(KEY, "<br>\n") + "</pre>" + "y" * 40, KEY
    elif encoding == "crlf":
        body, lines = "x" * 900 + "\r\n" + _pem_with(KEY, "\r\n") + "\r\n" + "y" * 40, KEY
    else:
        body = _php_json({"pad": "x" * 900, "k": _pem_with(KEY) + "\n", "z": "y" * 40})
        lines = KEY_PHP
    for result in _scan_both(tmp_path, body, body_cap=cap):
        _assert_no_lines(result, lines)


@pytest.mark.parametrize("width", [58, 64, 76, 80])
def test_headless_unterminated_run_of_any_common_width_is_never_stored(tmp_path, width):
    lines = _key_lines(width=width)
    body = "x" * 900 + "\n" + _pem_with(lines, end=False) + "\n<p>tail text</p>"
    live, replayed = _scan_both(tmp_path, body, legacy=True, body_cap=1200)
    fixture = " ".join(b or "" for b in _fixture_bodies(tmp_path))
    assert "private_key" not in fixture and "BEGIN" not in fixture  # really headless
    for result in (live, replayed):
        _assert_no_lines(result, lines)


def test_text_after_an_end_line_is_still_kept_in_every_encoding(tmp_path):
    body = "<pre>" + _pem_with(KEY, "<br>\n") + "</pre><p>Keep this closing sentence.</p>"
    for result in _scan_both(tmp_path, body):
        f = only(result, "web-secret-in-response")
        assert "Keep this closing sentence." in f.evidence[0].test.response.body
        _assert_no_lines(result, KEY)


def test_round_three_patterns_stay_linear():
    import time

    from scanners.web.scanner import _redacted

    line = KEY[0]
    hostile = (
        (line + "<br>\n") * 3000 + "x",
        (line + "&#10;" + "a b ") * 3000,
        ("ab\\/" * 20 + "\\n") * 2000 + "-----END PRIVATE KEY-----",
        "\n" + " " * 200_000 + "x",
        ("a " * 100_000) + "-----END PRIVATE KEY-----",
        ("<br>" * 50_000) + "-----END PRIVATE KEY-----",
        ";" * 200_000,
        ("-----END PRIVATE KEY-----\n" + "A" * 50 + " ") * 4000,
        ("\n... [9 bytes truncated] ...\n" + "<b>x</b> " * 10) * 2000 + "-----END PRIVATE KEY-----",
        ("\n... [9 bytes truncated] ...\nab -----END PRIVATE KEY-----") * 4000,
    )
    for text in hostile:
        started = time.monotonic()
        _redacted(text)
        assert time.monotonic() - started < 1.5, text[:40]


# --- Fix round 4: an orphan END after core's truncation marker, any separator ----


def _tail_straddle(keytext):
    """BEGIN falls in core's gap at the default cap; the END line survives in the tail."""
    return "x" * (HALF + 5000) + keytext + "y" * (HALF - len(keytext) // 2)


_BEGIN, _END = "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize(
    "keytext",
    [
        pytest.param('<input value="' + _pem_with(KEY, "&#x0A;") + '">', id="hex-entity-0A"),
        pytest.param('<input value="' + _pem_with(KEY, "&#X0D;&#X0A;") + '">', id="hex-0D0A"),
        pytest.param(_BEGIN + '<BR class="x">' + '<BR class="x">'.join(KEY) + _END, id="br-attr"),
        pytest.param("<p>KEY=" + _BEGIN + " " + " ".join(KEY) + " " + _END + "</p>", id="spaces"),
        pytest.param(
            "<pre>" + _BEGIN + "\n" + "".join(f"{x}<!---->\n" for x in KEY) + _END + "</pre>",
            id="comment-each-line",
        ),
        pytest.param(
            _BEGIN + "".join(f"<tr><td>{x}</td></tr>" for x in KEY) + _END, id="table-cells"
        ),
        pytest.param(
            _BEGIN + "\n" + "".join(f"key: {x}\n" for x in KEY) + _END, id="prefixed-lines"
        ),
    ],
)
def test_orphan_end_after_the_truncation_marker_never_stores_key_lines(tmp_path, keytext):
    live, replayed = _scan_both(tmp_path, _tail_straddle(keytext), legacy=True)
    fixture = " ".join(b or "" for b in _fixture_bodies(tmp_path))
    assert "bytes truncated" in fixture and "private_key" not in fixture  # BEGIN in the gap
    assert "END RSA PRIVATE KEY" in fixture  # and END survives in the tail
    for result in (live, replayed):
        _assert_no_lines(result, KEY)
    body = only(replayed, "web-secret-in-response").evidence[0].test.response.body
    assert "bytes truncated] ...\n[redacted:private_key]" in body  # the cut stays visible
    assert body.endswith("y" * 100)  # text after the END line is kept


def test_core_now_records_fixtures_with_no_key_material(tmp_path):
    """D21: the fixture on disk is clean, not merely the evidence built from it."""
    _scan_both(tmp_path, "x" * 1000 + "\n" + _pem() + "\n" + "y" * 40, body_cap=400)
    fixture = " ".join(b or "" for b in _fixture_bodies(tmp_path))
    assert "END RSA PRIVATE KEY" not in fixture
    for line in _pem().splitlines()[1:-1]:
        assert line not in fixture and line[-24:] not in fixture
