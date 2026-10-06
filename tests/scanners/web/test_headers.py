from scanners.web import headers as h


def test_get_is_case_insensitive():
    assert h.get({"X-Frame-Options": "DENY"}, "x-frame-options") == "DENY"
    assert h.get({}, "x") is None


def test_hsts():
    assert h.hsts_verdict(None) == ("missing", None)
    assert h.hsts_verdict("  ") == ("missing", None)
    assert h.hsts_verdict("max-age=31536000; includeSubDomains") == ("ok", 31536000)
    assert h.hsts_verdict("max-age=300") == ("weak", 300)
    assert h.hsts_verdict("max-age=15768000")[0] == "ok"
    assert h.hsts_verdict("max-age=15767999")[0] == "weak"
    assert h.hsts_verdict('max-age="31536000"') == ("ok", 31536000)
    assert h.hsts_verdict("includeSubDomains") == ("weak", None)


def test_hsts_duplicate_header_first_wins():  # Review Focus 3
    assert h.hsts_verdict("max-age=300, max-age=31536000") == ("weak", 300)


def test_xfo():
    assert h.xfo_protects("DENY") and h.xfo_protects("sameorigin")
    assert h.xfo_protects("DENY, DENY")  # Review Focus 3
    assert not h.xfo_protects("ALLOW-FROM https://a.test")
    assert not h.xfo_protects("DENY, ALLOWALL")
    assert not h.xfo_protects(None) and not h.xfo_protects("")


def test_xcto():
    assert h.xcto_ok("nosniff") and h.xcto_ok("NoSniff") and h.xcto_ok("nosniff, nosniff")
    assert not h.xcto_ok(None) and not h.xcto_ok("sniff")


def test_referrer():
    assert h.referrer_verdict(None) == ("missing", None)
    assert h.referrer_verdict("unsafe-url") == ("unsafe", "unsafe-url")
    assert h.referrer_verdict("no-referrer-when-downgrade")[0] == "unsafe"
    assert h.referrer_verdict("strict-origin-when-cross-origin")[0] == "ok"
    assert h.referrer_verdict("unsafe-url, strict-origin") == ("ok", "strict-origin")
    assert h.referrer_verdict("bogus") == ("missing", None)
    assert h.referrer_verdict("strict-origin, bogus") == ("ok", "strict-origin")


def test_cors():
    assert h.cors_wildcard("*") and not h.cors_wildcard("https://a.test")
    assert not h.cors_wildcard(None)
