from core.http import CapturedResponse
from scanners.domscout.takeover import FINGERPRINTS, match_cname


def _resp(status: int, text: str) -> CapturedResponse:
    return CapturedResponse(status_code=status, text=text, headers={}, captured={}, url="https://x")


def test_github_pages_positive_needs_http_body() -> None:
    fp = match_cname("victim.github.io")
    assert fp is not None and fp.service == "github-pages"
    r = fp.evaluate(
        cname_target_nxdomain=False,
        http=_resp(404, "There isn't a GitHub Pages site here."),
    )
    assert r.matched is True
    assert r.needs_http is True


def test_github_pages_negative_live_site() -> None:
    fp = match_cname("victim.github.io")
    assert fp is not None
    r = fp.evaluate(cname_target_nxdomain=False, http=_resp(200, "<html>real site</html>"))
    assert r.matched is False


def test_s3_positive_is_dns_only() -> None:
    fp = match_cname("bucket.s3.amazonaws.com")
    assert fp is not None
    r = fp.evaluate(cname_target_nxdomain=True, http=None)
    assert r.matched is True and r.needs_http is False


def test_heroku_match_and_nonmatch() -> None:
    assert match_cname("app.herokudns.com") is not None
    assert match_cname("app.herokuapp.com") is not None
    assert match_cname("not-a-known-service.example.com") is None


def test_fingerprints_have_public_sources() -> None:
    assert len(FINGERPRINTS) >= 3
    for fp in FINGERPRINTS:
        assert fp.source.startswith("https://")
