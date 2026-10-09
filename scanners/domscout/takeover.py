"""Subdomain-takeover fingerprint adapters.

Pure matching logic only: no network, no DNS resolution, no HTTP calls. The
caller (domscout's DNS/CT enumeration and its HTTP client, both driven
through `ScanContext`) supplies the facts — whether a CNAME target resolved
to NXDOMAIN, and an already-captured HTTP response, if one was fetched — and
this module decides whether a fingerprint matches.

Every fingerprint's `source` is a public, first-party advisory or vendor
document (per ADR-024) — never copied from a GPL tool's fingerprint
database (CLAUDE.md hard constraint 4, on Wappalyzer/GPL data specifically,
applies to the same category of risk here).

**What each provider serves is recorded, not assumed** (D31, ADR-027):
`corpus/crosscheck/d31-provider-responses/`. For an unclaimed name every
provider's endpoint *resolves*, so no fingerprint decides on DNS alone. And for
a custom domain the unclaimed page is reachable only over plain HTTP, because
the provider's certificate does not cover the customer's name. So every
fingerprint judges a body fetched over `http://` (`scheme`).

A match here is `suspected` at most — the takeover claim is never stronger
than that this module can support; capping to that state is the scanner's
job (`core/state.py`), not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.http import CapturedResponse


@dataclass(frozen=True)
class FingerprintResult:
    matched: bool
    needs_http: bool
    detail: str


class TakeoverFingerprint(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def service(self) -> str: ...

    @property
    def source(self) -> str: ...

    @property
    def scheme(self) -> str: ...

    def matches_cname(self, target: str) -> bool: ...

    def evaluate(
        self, cname_target_nxdomain: bool, http: CapturedResponse | None
    ) -> FingerprintResult: ...


@dataclass(frozen=True)
class _SuffixCnameMixin:
    name: str
    service: str
    source: str
    suffixes: tuple[str, ...]
    scheme: str = "http"
    """Recorded 2026-10-10: over https a custom domain fails the provider's
    certificate (or the connection is reset), so the unclaimed page is never seen."""

    def matches_cname(self, target: str) -> bool:
        lowered = target.lower().rstrip(".")
        return any(lowered.endswith(suffix) for suffix in self.suffixes)


@dataclass(frozen=True)
class GitHubPagesFingerprint(_SuffixCnameMixin):
    """GitHub Pages: the takeover signal is the 404 body text, not DNS alone —
    a CNAME to `*.github.io` that still resolves and serves a live site is
    not dangling.

    Source: GitHub's own docs on the exact error text served for an
    unclaimed/mismatched custom domain.
    https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages
    """

    body_needle: str = "There isn't a GitHub Pages site here."

    def evaluate(
        self, cname_target_nxdomain: bool, http: CapturedResponse | None
    ) -> FingerprintResult:
        del cname_target_nxdomain  # GitHub Pages' IPs don't NXDOMAIN; the body is the signal.
        if http is None:
            return FingerprintResult(
                matched=False, needs_http=True, detail="no HTTP response captured"
            )
        if self.body_needle in http.text:
            return FingerprintResult(
                matched=True,
                needs_http=True,
                detail=f"response body contains '{self.body_needle}'",
            )
        return FingerprintResult(
            matched=False, needs_http=True, detail="response body did not match the takeover page"
        )


@dataclass(frozen=True)
class _BodyFingerprint(_SuffixCnameMixin):
    """A 404 carrying the provider's own "nothing is here" text is the signal."""

    body_needle: str = ""

    def evaluate(
        self, cname_target_nxdomain: bool, http: CapturedResponse | None
    ) -> FingerprintResult:
        del cname_target_nxdomain  # recorded: the provider's name resolves either way
        if http is None:
            return FingerprintResult(
                matched=False, needs_http=True, detail="no HTTP response captured"
            )
        if http.status_code == 404 and self.body_needle in http.text:
            return FingerprintResult(
                matched=True,
                needs_http=True,
                detail=f"HTTP 404 whose body contains '{self.body_needle}'",
            )
        return FingerprintResult(
            matched=False,
            needs_http=True,
            detail=f"HTTP {http.status_code}, not the provider's unclaimed-name response",
        )


@dataclass(frozen=True)
class S3Fingerprint(_BodyFingerprint):
    """AWS S3: an unclaimed bucket answers `404` with `NoSuchBucket`, on the REST
    endpoint (XML `<Code>NoSuchBucket</Code>`) and the website endpoint (HTML
    `Code: NoSuchBucket`), both recorded. `AccessDenied` or `NoSuchKey` means the
    bucket exists.
    """

    body_needle: str = "NoSuchBucket"

    def matches_cname(self, target: str) -> bool:
        # bucket.s3.amazonaws.com, bucket.s3.<region>.amazonaws.com,
        # bucket.s3-website-<region>.amazonaws.com, bucket.s3-website.<region>...
        labels = target.lower().rstrip(".").split(".")
        return labels[-2:] == ["amazonaws", "com"] and any(
            label == "s3" or label.startswith("s3-website") for label in labels[1:-2]
        )


@dataclass(frozen=True)
class HerokuFingerprint(_BodyFingerprint):
    """Heroku: an unclaimed app or detached domain answers `404` from
    `heroku-router` with a page titled "No such app" (recorded)."""

    body_needle: str = "<title>No such app</title>"


FINGERPRINTS: list[TakeoverFingerprint] = [
    GitHubPagesFingerprint(
        name="GitHub Pages",
        service="github-pages",
        source=(
            "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-"
            "github-pages-site/verifying-your-custom-domain-for-github-pages"
        ),
        suffixes=(".github.io",),
    ),
    S3Fingerprint(
        name="AWS S3",
        service="aws-s3",
        source="https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
        suffixes=(".s3.amazonaws.com",),
    ),
    HerokuFingerprint(
        name="Heroku",
        service="heroku",
        source="https://devcenter.heroku.com/articles/custom-domains",
        suffixes=(".herokudns.com", ".herokuapp.com"),
    ),
]


def match_cname(target: str) -> TakeoverFingerprint | None:
    for fp in FINGERPRINTS:
        if fp.matches_cname(target):
            return fp
    return None
