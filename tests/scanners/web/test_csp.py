"""Tests for CSP parsing and script-policy grading."""

from scanners.web import csp


def weak(value):
    return csp.effective_weaknesses(csp.parse(value))


def test_strict_policy():
    assert weak("default-src 'self'; script-src 'self'") == frozenset()


def test_unsafe_inline_and_its_nonce_hash_exemptions():
    assert "unsafe-inline" in weak("script-src 'self' 'unsafe-inline'")
    assert "unsafe-inline" not in weak("script-src 'nonce-abc' 'unsafe-inline'")
    assert "unsafe-inline" not in weak("script-src 'sha256-xyz' 'unsafe-inline'")
    assert "unsafe-inline" not in weak("script-src 'strict-dynamic' 'unsafe-inline'")


def test_eval_wildcard_schemes():
    assert "unsafe-eval" in weak("script-src 'unsafe-eval'")
    assert weak("script-src * http: data:") >= {"wildcard", "scheme-http", "scheme-data"}


def test_default_src_fallback_and_override():
    assert "unsafe-inline" in weak("default-src 'unsafe-inline'")
    assert weak("default-src 'unsafe-inline'; script-src 'self'") == frozenset()


def test_policy_without_script_control_allows_everything():
    assert weak("img-src 'self'") == csp.ALL_WEAKNESSES
    assert not csp.restricts_scripts(csp.parse("img-src 'self'"))
    assert csp.restricts_scripts(csp.parse("default-src 'self'"))


def test_multiple_policies_intersect():
    assert weak("script-src 'unsafe-inline', script-src 'self'") == frozenset()
    assert "unsafe-eval" in weak("script-src 'unsafe-eval', default-src 'unsafe-eval'")


def test_first_duplicate_directive_wins():
    assert weak("script-src 'self'; script-src 'unsafe-inline'") == frozenset()


def test_frame_ancestors():
    assert csp.has_frame_ancestors(csp.parse("frame-ancestors 'none'"))
    assert not csp.has_frame_ancestors(csp.parse("default-src 'self'"))


def test_empty_and_case():
    assert csp.parse(None) == [] and csp.parse("") == [] and weak(None) == frozenset()
    assert "unsafe-inline" in weak("Script-Src 'UNSAFE-INLINE'")
