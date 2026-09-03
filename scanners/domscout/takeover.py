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
class S3Fingerprint(_SuffixCnameMixin):
    """AWS S3: a dangling bucket CNAME is provable from DNS alone — the
    bucket target NXDOMAINs when the bucket has been deleted or was never
    created, before any HTTP request is made.

    Source: AWS's own guidance on S3 website endpoints and bucket naming,
    describing the CNAME-to-bucket-endpoint pattern this fingerprint checks.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
    """

    def evaluate(
        self, cname_target_nxdomain: bool, http: CapturedResponse | None
    ) -> FingerprintResult:
        del http  # DNS alone is conclusive for a dangling S3 CNAME.
        if cname_target_nxdomain:
            return FingerprintResult(
                matched=True,
                needs_http=False,
                detail="CNAME target is an S3 bucket endpoint that does not resolve (NXDOMAIN)",
            )
        return FingerprintResult(
            matched=False, needs_http=False, detail="CNAME target resolves; bucket is not dangling"
        )


@dataclass(frozen=True)
class HerokuFingerprint(_SuffixCnameMixin):
    """Heroku: like S3, a dangling Heroku app CNAME NXDOMAINs at the DNS
    layer once the app is destroyed or the domain detached.

    Source: Heroku's own custom-domains documentation, describing the
    `herokudns.com` / `herokuapp.com` CNAME targets this fingerprint checks.
    https://devcenter.heroku.com/articles/custom-domains
    """

    def evaluate(
        self, cname_target_nxdomain: bool, http: CapturedResponse | None
    ) -> FingerprintResult:
        del http
        if cname_target_nxdomain:
            return FingerprintResult(
                matched=True,
                needs_http=False,
                detail="CNAME target is a Heroku app endpoint that does not resolve (NXDOMAIN)",
            )
        return FingerprintResult(
            matched=False, needs_http=False, detail="CNAME target resolves; app is not dangling"
        )


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
