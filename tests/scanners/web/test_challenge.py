from scanners.web import challenge


def test_cloudflare_header():
    assert challenge.detect(403, {"cf-mitigated": "challenge"}, "") == "Cloudflare challenge"


def test_cloudflare_body_marker_on_error_status():
    body = '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"></script>'
    assert challenge.detect(503, {}, body) == "Cloudflare challenge"
    assert challenge.detect(200, {}, body) is None


def test_akamai_block():
    assert challenge.detect(403, {"Server": "AkamaiGHost"}, "<H1>Access Denied</H1>") == (
        "Akamai edge block"
    )


def test_ordinary_cdn_page_is_not_a_challenge():
    assert challenge.detect(200, {"server": "cloudflare", "cf-ray": "x"}, "<p>hi</p>") is None
