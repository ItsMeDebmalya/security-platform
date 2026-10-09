from pathlib import Path

import pytest

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


# D31: what the providers actually serve for an unclaimed name, recorded 2026-10-10
# (corpus/crosscheck/d31-provider-responses/). Every one of these names resolves,
# so a DNS-only fingerprint could never fire; the body over plain HTTP is the signal.
EVIDENCE = Path(__file__).resolve().parents[3] / "corpus" / "crosscheck" / "d31-provider-responses"
S3_REST = (EVIDENCE / "s3-rest-nosuchbucket.xml").read_text()
S3_WEBSITE = (EVIDENCE / "s3-website-nosuchbucket.html").read_text()
HEROKU = (EVIDENCE / "heroku-no-such-app.html").read_text()


@pytest.mark.parametrize("body", [S3_REST, S3_WEBSITE], ids=["rest", "website"])
def test_s3_matches_the_recorded_no_such_bucket_response(body) -> None:
    fp = match_cname("bucket.s3.amazonaws.com")
    assert fp is not None
    r = fp.evaluate(cname_target_nxdomain=False, http=_resp(404, body))
    assert r.matched is True and r.needs_http is True


def test_s3_never_matches_on_dns_alone() -> None:
    fp = match_cname("bucket.s3.amazonaws.com")
    assert fp is not None
    r = fp.evaluate(cname_target_nxdomain=True, http=None)
    assert r.matched is False and r.needs_http is True


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"),
        (200, "<html>a real static site</html>"),
        (404, "<Error><Code>NoSuchKey</Code></Error>"),
    ],
    ids=["private-bucket", "live-site", "missing-key-in-live-bucket"],
)
def test_s3_does_not_match_a_bucket_that_exists(status, body) -> None:
    fp = match_cname("bucket.s3.amazonaws.com")
    assert fp is not None
    assert fp.evaluate(cname_target_nxdomain=False, http=_resp(status, body)).matched is False


@pytest.mark.parametrize(
    "target",
    [
        "bucket.s3.amazonaws.com",
        "bucket.s3.us-east-1.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "bucket.s3-website.eu-west-2.amazonaws.com",
    ],
)
def test_s3_rest_and_website_endpoints_are_recognised(target) -> None:
    fp = match_cname(target)
    assert fp is not None and fp.service == "aws-s3"


def test_an_unrelated_amazonaws_name_is_not_s3() -> None:
    assert match_cname("ec2-1-2-3-4.compute-1.amazonaws.com") is None


def test_heroku_matches_the_recorded_no_such_app_response() -> None:
    fp = match_cname("app.herokuapp.com")
    assert fp is not None and fp.service == "heroku"
    assert fp.evaluate(cname_target_nxdomain=False, http=_resp(404, HEROKU)).matched is True
    assert fp.evaluate(cname_target_nxdomain=True, http=None).matched is False
    assert (
        fp.evaluate(cname_target_nxdomain=False, http=_resp(200, "<html>live app</html>")).matched
        is False
    )


def test_heroku_match_and_nonmatch() -> None:
    assert match_cname("app.herokudns.com") is not None
    assert match_cname("app.herokuapp.com") is not None
    assert match_cname("not-a-known-service.example.com") is None


def test_every_fingerprint_fetches_over_plain_http() -> None:
    """Recorded: for a custom domain, each provider's certificate does not cover it,
    so over https the unclaimed page is never reached (README in the evidence dir)."""
    assert all(fp.scheme == "http" for fp in FINGERPRINTS)


def test_fingerprints_have_public_sources() -> None:
    assert len(FINGERPRINTS) >= 3
    for fp in FINGERPRINTS:
        assert fp.source.startswith("https://")
