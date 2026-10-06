"""The check catalogue: severity, likelihood ratio, and why each is what it is.

Every entry is a promise made in docs/10-measurement.md: a detection does not
ship without a stated independence class and a hand-assigned prior with a
written justification. All 21 checks are Light and passive under ADR-023 —
each reads what an ordinary visitor's GET returns, nothing malformed and
nothing that changes state.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.authz import checks_require_authorisation
from core.models import Mode

HTTP_HEADER = "http_header"
"""A response header exactly as served (after any CDN edge)."""

HTML_DOCUMENT = "html_document"
"""The parsed body of a same-origin document — HTML markup, robots.txt,
security.txt — read for itself, independent of the headers it came with."""

ERROR_PAGE = "error_page"
"""The body of the deterministic 404 control: what the site serves for a path
that cannot exist."""

AUTOINDEX = "autoindex"
"""A web server's generated directory listing."""

VERSION_STRING = "version_string"
"""A version number read from a header or markup. Versions lie — distributions
backport fixes without changing them — so this class only ever feeds
version_only findings."""


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: str
    likelihood_ratio: float
    independence_class: str
    justification: str
    impact: str
    remediation: str
    passive: bool
    """0b.6: no default, deliberately — a check with no opinion fails to
    construct rather than reading as passive by omission."""
    mode: str = "light"


_HEADER_LR = 40.0
_HEADER_WHY = (
    "a response header is read directly from what the server sent; the only way it is wrong "
    "is if we did not see what visitors see, which the 404-control validation and the "
    "challenge-page rule address"
)

CHECKS: dict[str, Check] = {
    c.check_id: c
    for c in [
        Check(
            "web-https-redirect-missing",
            "Plain HTTP is served instead of redirecting to HTTPS",
            "medium",
            _HEADER_LR,
            HTTP_HEADER,
            "a 2xx over plain HTTP while HTTPS is available is directly observed",
            "Visitors who type the bare name or follow an old http:// link use an unencrypted "
            "connection that a network attacker can read or modify.",
            "Redirect every plain-HTTP request to the same path over HTTPS (301), then add HSTS.",
            passive=True,
        ),
        Check(
            "web-hsts-missing",
            "HTTPS responses carry no Strict-Transport-Security header",
            "medium",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Without HSTS a browser will still try plain HTTP first, so a network attacker "
            "can strip the connection to HTTP before the redirect happens.",
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS "
            "response.",
            passive=True,
        ),
        Check(
            "web-hsts-weak",
            "Strict-Transport-Security max-age is shorter than six months",
            "low",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "A short max-age lets browsers forget the HTTPS-only rule quickly, reopening the "
            "downgrade window HSTS exists to close.",
            "Raise max-age to at least 15768000 (six months); 31536000 is the common choice.",
            passive=True,
        ),
        Check(
            "web-csp-missing",
            "No Content-Security-Policy is set",
            "medium",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Without a CSP, any script injection (XSS) runs with the page's full privileges.",
            "Add a Content-Security-Policy that restricts script-src, starting from "
            "default-src 'self'.",
            passive=True,
        ),
        Check(
            "web-csp-weak",
            "The Content-Security-Policy does not restrict scripts effectively",
            "medium",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "A policy that allows inline script, eval, any host or plain-HTTP/data: scripts "
            "does not stop the script injection a CSP is meant to contain.",
            "Remove 'unsafe-inline' (use nonces or hashes), 'unsafe-eval', '*', http: and data: "
            "from script-src / default-src.",
            passive=True,
        ),
        Check(
            "web-clickjacking-unprotected",
            "The page can be framed by any site",
            "medium",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Another site can load this page invisibly in a frame and trick users into "
            "clicking on it (clickjacking).",
            "Send Content-Security-Policy: frame-ancestors 'self' (or 'none'), and "
            "X-Frame-Options: DENY for older browsers.",
            passive=True,
        ),
        Check(
            "web-xcto-missing",
            "X-Content-Type-Options: nosniff is not set",
            "low",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Browsers may guess a response's type, letting an uploaded file be executed as "
            "script or style.",
            "Send X-Content-Type-Options: nosniff on every response.",
            passive=True,
        ),
        Check(
            "web-referrer-policy-unsafe",
            "Referrer-Policy sends full URLs to other sites",
            "low",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Full URLs, including any tokens or identifiers in paths and query strings, are "
            "sent to every site this page links to or loads from.",
            "Use Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
            passive=True,
        ),
        Check(
            "web-referrer-policy-missing",
            "No Referrer-Policy is set",
            "info",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Browsers have defaulted to strict-origin-when-cross-origin since 2020-21, so the "
            "practical exposure is small; recorded as posture, not as a weakness.",
            "Set Referrer-Policy explicitly so the behaviour does not depend on browser defaults.",
            passive=True,
        ),
        Check(
            "web-cors-wildcard",
            "Access-Control-Allow-Origin: * on the root response",
            "low",
            _HEADER_LR,
            HTTP_HEADER,
            _HEADER_WHY,
            "Any website can read this response from a visitor's browser. Harmless for "
            "public, credential-free content; a leak if the response is ever personalised.",
            "Send Access-Control-Allow-Origin only for origins that need it, or omit it on "
            "pages that are not an API.",
            passive=True,
        ),
        Check(
            "web-mixed-content",
            "The HTTPS page references scripts or stylesheets over HTTP",
            "low",
            40.0,
            HTML_DOCUMENT,
            "the http:// URL is read verbatim from the page's own markup",
            "Current browsers block mixed active content, so the page is partly broken; on "
            "an old browser the resource could be modified in transit.",
            "Load every script and stylesheet over https://.",
            passive=True,
        ),
        Check(
            "web-sri-missing",
            "Cross-origin scripts are loaded without Subresource Integrity",
            "low",
            40.0,
            HTML_DOCUMENT,
            "the absence of an integrity attribute is read verbatim from the markup",
            "If the third-party host is compromised, its altered script runs on this page "
            "unchecked.",
            "Add integrity and crossorigin attributes to third-party script tags, or self-host "
            "the scripts.",
            passive=True,
        ),
        Check(
            "web-version-disclosure",
            "Software versions are exposed in responses",
            "low",
            40.0,
            HTTP_HEADER,
            "the version string is read verbatim from the response",
            "An exact version tells an attacker which known vulnerabilities to try first.",
            "Remove version numbers from Server, X-Powered-By and generator tags "
            "(e.g. nginx server_tokens off, PHP expose_php=Off).",
            passive=True,
        ),
        Check(
            "web-error-disclosure",
            "Error pages expose stack traces or internal details",
            "medium",
            20.0,
            ERROR_PAGE,
            "a stack-trace signature on the 404 control is strong but signatures can occur "
            "in ordinary content, so the ratio sits below a header read",
            "Stack traces reveal file paths, framework versions and code structure that help "
            "an attacker target the application.",
            "Serve generic error pages in production and log details server-side only.",
            passive=True,
        ),
        Check(
            "web-debug-mode",
            "The application is running with debug mode enabled",
            "high",
            40.0,
            ERROR_PAGE,
            "a framework's own debug-mode page text on the 404 control is unambiguous",
            "Debug pages expose configuration, URL routes and internals, and debug mode often "
            "disables production safeguards.",
            "Turn debug mode off in production (e.g. Django DEBUG = False).",
            passive=True,
        ),
        Check(
            "web-secret-in-response",
            "A credential-shaped secret appears in a public response",
            "high",
            30.0,
            HTML_DOCUMENT,
            "the secret pattern matched core's capture-time redaction list; patterns can "
            "match documentation examples, so the ratio sits below a header read",
            "Anyone who loads the page can copy the credential and use it.",
            "Revoke and rotate the credential immediately, then remove it from the page.",
            passive=True,
        ),
        Check(
            "web-directory-listing",
            "Directory listing is enabled",
            "medium",
            30.0,
            AUTOINDEX,
            "a web server's own autoindex page is unambiguous markup",
            "Anyone can browse every file in the directory, including ones never linked.",
            "Disable directory listing (nginx autoindex off; Apache Options -Indexes).",
            passive=True,
        ),
        Check(
            "web-technology",
            "Technologies identified on this site",
            "info",
            40.0,
            HTML_DOCUMENT,
            "inventory read from headers and markup, not a claim of weakness",
            "Inventory only.",
            "No action required.",
            passive=True,
        ),
        Check(
            "web-robots-paths",
            "robots.txt lists paths and sitemaps",
            "info",
            40.0,
            HTML_DOCUMENT,
            "inventory read verbatim from robots.txt",
            "Disallowed paths are a public list; they are not access control.",
            "Never rely on robots.txt to hide a sensitive path.",
            passive=True,
        ),
        Check(
            "web-security-txt-missing",
            "No security.txt (RFC 9116) is published",
            "info",
            40.0,
            HTML_DOCUMENT,
            "presence is read directly from /.well-known/security.txt",
            "Researchers who find a problem have no published way to report it.",
            "Publish /.well-known/security.txt with Contact and Expires fields.",
            passive=True,
        ),
        Check(
            "web-component-eol",
            "A component version is past its vendor end-of-life",
            "medium",
            40.0,
            VERSION_STRING,
            "the version is read verbatim, but versions lie; capped by version_only",
            "End-of-life software no longer receives security fixes from its vendor.",
            "Upgrade to a supported release, or confirm your distribution still patches it.",
            passive=True,
        ),
    ]
}


def requires_authorisation(mode: Mode) -> bool:
    """Computed from the catalogue, never hand-set: an active check added later
    flips this automatically."""
    return checks_require_authorisation(CHECKS.values(), mode=mode)
