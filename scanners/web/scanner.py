"""The Web scanner — the Website Scanner's Light mode (Tool 4a).

Passive and bounded: `fetch.gather` makes at most 12 scanner-issued GETs once
(in-scope redirect hops are additional - ledger D26); this module only judges
what came back. Design: docs/superpowers/specs/
2026-10-02-web-light-design.md.

- A header claim is validated by re-reading the policy on the 404 control.
  That shows the policy is origin-wide, not one route's quirk. It does NOT show
  independent infrastructure - both responses come through the same edge.
- A response we could not read is inconclusive, never clear.
- A root that ends on a 3xx is a redirect, never a rendered page: page-security
  checks are inconclusive on it; HSTS and server-identity checks still judge it.
- State is derived by core/state.py through Finding.create, never set here.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.evidence import capture_http_pair, redact_body
from core.http import HttpClient
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.redaction import cap_prefix, redact_text
from core.registry import register
from core.scanner import BaseScanner, UnsupportedTargetError
from scanners.web import csp, disclosure, eol, fingerprint, headers, html, listing
from scanners.web.checks import CHECKS, HTML_DOCUMENT, HTTP_HEADER, VERSION_STRING, Check
from scanners.web.checks import requires_authorisation as _requires_authorisation
from scanners.web.fetch import Fetched, gather, origins

VALIDATION_METHOD = "second_same_origin_response"
NO_VERDICT = frozenset(
    {"timeout", "waf_block", "blocked_prerequisite", "ambiguous_response", "rate_limited"}
)
VALIDATION_NOTES = {
    "passed": (
        " Validated on a second same-origin response (the 404 control). Both responses came "
        "through the same edge, so this shows the policy is origin-wide, not that independent "
        "infrastructure agrees."
    ),
    "failed": (
        " The 404 control does not show the same deficiency, so the header appears to be set "
        "per route rather than missing site-wide; reported at reduced confidence."
    ),
    "unavailable": " The 404 control was unusable, so this could not be validated.",
}
REDIRECT_NOTES = {
    "passed": (
        " Validated on a second plain-HTTP request (the 404 control path), which was also "
        "served without redirecting. Both responses came through the same edge, so this shows "
        "the behaviour is host-wide, not that independent infrastructure agrees."
    ),
    "failed": (
        " The plain-HTTP 404 control path does redirect to HTTPS, so the missing redirect "
        "appears to be specific to this path; reported at reduced confidence."
    ),
    "unavailable": " The plain-HTTP 404 control was unusable, so this could not be validated.",
}
HEADER_FAMILY = frozenset(
    {
        "web-https-redirect-missing",
        "web-hsts-missing",
        "web-hsts-weak",
        "web-csp-missing",
        "web-csp-weak",
        "web-clickjacking-unprotected",
        "web-xcto-missing",
        "web-referrer-policy-unsafe",
        "web-referrer-policy-missing",
        "web-cors-wildcard",
    }
)

DEFAULT_PORTS = {"https": 443, "http": 80}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

Url = tuple[str, str, int, str, str]
ROBOTS_LISTED = 20
DESCRIPTION_CAP = 2000
_INDEX = re.compile(r"/index\.(?:html?|php|aspx?|jsp)$", re.IGNORECASE)


def _decode_unreserved(path: str) -> str:
    """RFC 3986 6.2.2.2: percent-encoded unreserved characters equal their literal."""
    out, i = [], 0
    while i < len(path):
        chunk = path[i : i + 3]
        if path[i] == "%" and len(chunk) == 3 and unquote(chunk) in _UNRESERVED:
            out.append(unquote(chunk))
            i += 3
        else:
            out.append(path[i])
            i += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    segments: list[str] = []
    parts = path.split("/")
    for i, segment in enumerate(parts):
        last = i == len(parts) - 1
        if segment == "..":
            if len(segments) > 1:
                segments.pop()
            if last:
                segments.append("")
        elif segment == ".":
            if last:
                segments.append("")
        else:
            segments.append(segment)
    return "/".join(segments) or "/"


def _normalised(url: str) -> Url | None:
    """(scheme, host, port, path, query) for comparing two final URLs; None if
    unparseable, which callers treat as unusable. Normalises towards *equal*:
    two URLs that might name the same resource must not count as distinct.
    The fragment is dropped - it is never sent, so it names no other response."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if scheme not in DEFAULT_PORTS or not host:
        return None
    path = _decode_unreserved(parts.path or "/")
    while "//" in path:  # most servers merge slashes; never treat // as distinct
        path = path.replace("//", "/")
    path = _remove_dot_segments(path if path.startswith("/") else "/" + path)
    path = _INDEX.sub("/", path)  # /index.html is the directory's default document
    return scheme, host, port or DEFAULT_PORTS[scheme], path, parts.query


Judge = Callable[[dict[str, str], str], tuple[bool, str]]
"""(headers, body) -> (deficient?, what was observed, quoted)."""


@register
class WebScanner(BaseScanner):
    name = "web"
    version = "1.0.4"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain", "url"})

    def validate(self, target: Asset, mode: Mode = "light") -> None:
        super().validate(target, mode)
        try:
            origins(target)
        except ValueError as exc:  # urlsplit: a port that is not a number in range
            raise UnsupportedTargetError(
                f'web cannot read the port in "{target.value.strip()}" ({exc}); '
                "give a URL with a numeric port, or none"
            ) from exc

    def requires_authorisation(self, mode: Mode) -> bool:
        return _requires_authorisation(mode)

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        http = ctx.http
        assert isinstance(http, HttpClient), "web needs an HTTP client from the context"
        return _Scan(self, target, mode, ctx, http).execute()


# --- judges: pure functions over (headers, body) -----------------------------


def _q(value: str | None) -> str:
    return "absent" if value is None else f'"{value}"'


def _q_all(values: tuple[str, ...]) -> str:
    return ", ".join(f'"{v}"' for v in values) if values else "none"


def _meta_csp(body: str) -> tuple[str, ...]:
    return html.extract(body, "about:blank").meta_csp if body else ()


def _csp_missing(h: dict[str, str], body: str) -> tuple[bool, str]:
    header = headers.get(h, "content-security-policy")
    meta = _meta_csp(body)
    return (
        header is None and not meta,
        f"Content-Security-Policy header {_q(header)}, <meta> policies {_q_all(meta)}",
    )


def _csp_weak(h: dict[str, str], body: str) -> tuple[bool, str]:
    header = headers.get(h, "content-security-policy")
    meta = _meta_csp(body)
    policies = csp.parse(header)
    for value in meta:
        policies.extend(csp.parse(value))
    if not policies:
        return False, "no policy"
    received = f"Content-Security-Policy header {_q(header)}, <meta> policies {_q_all(meta)}"
    if not csp.restricts_scripts(policies):
        return (
            True,
            f"{received}; no policy sets script-src or default-src, so scripts are unrestricted",
        )
    weak = csp.effective_weaknesses(policies)
    return bool(weak), f"{received}; the script policy allows: {', '.join(sorted(weak))}"


def _clickjacking(h: dict[str, str], body: str) -> tuple[bool, str]:
    xfo = headers.get(h, "x-frame-options")
    frame_ancestors = csp.has_frame_ancestors(csp.parse(headers.get(h, "content-security-policy")))
    return (
        not headers.xfo_protects(xfo) and not frame_ancestors,
        f"X-Frame-Options {_q(xfo)}, CSP frame-ancestors present: {frame_ancestors}",
    )


def _xcto(h: dict[str, str], body: str) -> tuple[bool, str]:
    value = headers.get(h, "x-content-type-options")
    return not headers.xcto_ok(value), f"X-Content-Type-Options {_q(value)}"


def _referrer_unsafe(h: dict[str, str], body: str) -> tuple[bool, str]:
    verdict, effective = headers.referrer_verdict(headers.get(h, "referrer-policy"))
    return verdict == "unsafe", f"effective Referrer-Policy {_q(effective)}"


def _referrer_missing(h: dict[str, str], body: str) -> tuple[bool, str]:
    verdict, _ = headers.referrer_verdict(headers.get(h, "referrer-policy"))
    return verdict == "missing", f"Referrer-Policy {_q(headers.get(h, 'referrer-policy'))}"


def _cors(h: dict[str, str], body: str) -> tuple[bool, str]:
    value = headers.get(h, "access-control-allow-origin")
    return headers.cors_wildcard(value), f"Access-Control-Allow-Origin {_q(value)}"


HEADER_POLICIES: tuple[tuple[str, Judge, bool], ...] = (
    ("web-csp-missing", _csp_missing, True),
    ("web-csp-weak", _csp_weak, True),
    ("web-clickjacking-unprotected", _clickjacking, True),
    ("web-xcto-missing", _xcto, True),
    ("web-referrer-policy-unsafe", _referrer_unsafe, True),
    ("web-referrer-policy-missing", _referrer_missing, False),
    ("web-cors-wildcard", _cors, True),
)
"""(check_id, judge, validate on the 404 control?)"""
POLICY_IDS = frozenset(c for c, _, _ in HEADER_POLICIES)


def _redirect_text(f: Fetched) -> str | None:
    """Why a root that ended on a 3xx says nothing about a page, or None if it did not."""
    if f.response is None or not 300 <= f.response.status_code < 400:
        return None
    location = headers.get(f.response.headers, "location") or "an unknown location"
    via = f" (after in-scope redirects, at {f.response.url})" if f.response.url != f.url else ""
    return (
        f"{f.url}{via} answered HTTP {f.response.status_code} redirecting to {location} — "
        "a redirect response is never rendered as a page, so its page-security headers "
        "describe nothing a visitor sees; scan the redirect target instead."
    )


REDIRECT_REMEDIATION = (
    "Scan the URL the redirect points to; that is the page visitors are shown, and its "
    "headers are the ones that protect them."
)


def _why_unusable(f: Fetched) -> tuple[str, str]:
    if f.failure == "waf_block":
        return "waf_block", (
            f"{f.url} answered with an anti-bot challenge or edge block, not the "
            "site itself, so nothing about the site can be read from it"
        )
    if f.failure == "rate_limited":
        return "rate_limited", f"{f.url} answered HTTP 429 (rate limited)"
    if f.response is None:
        reason = f.failure if f.failure in NO_VERDICT else "blocked_prerequisite"
        if f.detail:
            return reason, f"{f.url} could not be fetched: {f.detail}"
        return reason, f"{f.url} could not be fetched ({f.failure or 'not requested'})"
    return "ambiguous_response", (
        f"{f.url} answered HTTP {f.response.status_code}, a server "
        "error, so it may not reflect the site's configuration"
    )


def _request(f: Fetched) -> dict[str, Any]:
    return {"method": "GET", "url": _redacted(f.url)}


def _raw(f: Fetched) -> dict[str, Any]:
    if f.response is None:
        return {"status": 0, "headers": {}, "body": None, "elapsed_ms": 0}
    return {
        "status": f.response.status_code,
        "headers": {_redacted(k): _redacted(v) for k, v in f.response.headers.items()},
        "body": f.response.text,
        "elapsed_ms": f.response.captured.get("elapsed_ms"),
    }


class _Scan:
    """One run against one target. Gathers once, then judges."""

    def __init__(
        self, scanner: WebScanner, target: Asset, mode: Mode, ctx: ScanContext, http: HttpClient
    ) -> None:
        self.scanner, self.target, self.mode, self.ctx, self.http = (
            scanner,
            target,
            mode,
            ctx,
            http,
        )
        self.findings: list[Finding] = []
        self.checks: list[CheckRun] = []
        self.engine = ConfidenceEngine()
        self.fingerprints = fingerprint.load()
        self.eol_entries = eol.load()

    def execute(self) -> ScanResult:
        self.ctx.progress("fetching the site", 0.1)
        self.obs = gather(self.ctx, self.http, self.target)
        root = self.obs.root
        self.detections: list[fingerprint.Detection] = []
        if root.usable and root.response is not None:
            page = self.obs.page
            self.detections = fingerprint.detect(
                self.fingerprints,
                headers=root.response.headers,
                body=root.response.text,
                asset_urls=page.asset_urls if page else (),
                generator=page.generator if page else None,
            )
        self.edge = next((d.name for d in self.detections if d.category == "cdn"), None)

        self.ctx.progress("judging transport security", 0.4)
        self._check_https_redirect()
        self._check_hsts()
        self.ctx.progress("judging security headers", 0.55)
        self._check_header_policies()
        self.ctx.progress("judging page content", 0.7)
        self._check_page_content()
        self._check_secrets()
        self.ctx.progress("judging error pages and directories", 0.85)
        self._check_error_pages()
        self._check_listings()
        self._check_robots()
        self._check_security_txt()
        self.ctx.progress("done", 1.0)
        cost = self.ctx.cost.snapshot()
        return ScanResult(
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            target=self.target,
            mode=self.mode,
            findings=self.findings,
            errors=[],
            telemetry=Telemetry(
                checks_run=self.checks, requests=cost.requests, wall_ms=cost.wall_ms
            ),
            finished_at=datetime.now(UTC),
        )

    # --- transport -------------------------------------------------------

    def _check_https_redirect(self) -> None:
        check, loc = CHECKS["web-https-redirect-missing"], self.obs.root_path
        https, plain = self.obs.https_root, self.obs.http_root
        if not self._https_ok():
            reason, text = self._https_problem()
            self._inconclusive(
                check,
                loc,
                https,
                f"HTTPS could not be read: {text}. Whether plain "
                "HTTP should redirect to it cannot be judged.",
                reason=reason,
            )
            return
        if not plain.usable or plain.response is None:
            reason, text = _why_unusable(plain)
            self._inconclusive(
                check, loc, plain, f"Plain HTTP could not be read: {text}.", reason=reason
            )
            return
        status = plain.response.status_code
        if status >= 500:
            self._inconclusive(
                check,
                loc,
                plain,
                f"{plain.url} answered HTTP {status}, a server error, so whether it redirects "
                "to HTTPS cannot be judged.",
                reason="ambiguous_response",
            )
            return
        if plain.final_scheme == "https" or not 200 <= status < 300:
            self._clear(check, loc)
            return
        self._emit(
            check,
            loc,
            test=plain,
            control=https,
            description=(
                f"{plain.url} answered HTTP {status} over plain HTTP (final URL "
                f"{plain.response.url}) instead of redirecting, while HTTPS is "
                f"served at {https.url}"
            ),
            validation=self._validate_redirect(),
        )

    def _validate_redirect(self) -> dict[str, Any]:
        probe = self.obs.http_probe
        unavailable = {"attempted": False, "outcome": "unavailable", "method": VALIDATION_METHOD}
        if not probe.usable or probe.response is None or probe.response.status_code >= 500:
            return unavailable
        redirected = probe.final_scheme == "https" or 300 <= probe.response.status_code < 400
        # A control that redirected to HTTPS is itself a readable observation: the
        # missing redirect is path-specific. A "passed" needs a distinct same-scheme control.
        if not redirected and not self._control_usable(probe, self.obs.http_root):
            return unavailable
        return {
            "attempted": True,
            "outcome": "failed" if redirected else "passed",
            "method": VALIDATION_METHOD,
        }

    def _check_hsts(self) -> None:
        missing, weak = CHECKS["web-hsts-missing"], CHECKS["web-hsts-weak"]
        root, loc = self.obs.https_root, self.obs.root_path
        if not self._https_ok():
            reason, text = self._https_problem()
            for check in (missing, weak):
                self._inconclusive(check, loc, root, text + ".", reason=reason)
            return
        assert root.response is not None
        value = headers.get(root.response.headers, "strict-transport-security")
        verdict, age = headers.hsts_verdict(value)
        if verdict == "ok":
            self._clear(missing, loc)
            self._clear(weak, loc)
            return
        fired, other = (missing, weak) if verdict == "missing" else (weak, missing)

        def judge(h: dict[str, str], body: str) -> tuple[bool, str]:
            v, _ = headers.hsts_verdict(headers.get(h, "strict-transport-security"))
            return (v == "missing") if fired is missing else (v == "weak"), ""

        observed = (
            "no Strict-Transport-Security header"
            if verdict == "missing"
            else f"Strict-Transport-Security {_q(value)} (max-age {age})"
        )
        self._emit(
            fired,
            loc,
            test=root,
            control=self.obs.https_probe,
            description=f"{root.response.url} is served with {observed}",
            validation=self._validate_on_probe(judge, self.obs.https_probe, test=root),
        )
        self._clear(other, loc)

    # --- header policies ---------------------------------------------------

    def _check_header_policies(self) -> None:
        root, probe, loc = self.obs.root, self.obs.probe, self.obs.root_path
        checks = [CHECKS[c] for c, _, _ in HEADER_POLICIES]
        if not self._usable(root, checks):
            return
        assert root.response is not None
        redirect = _redirect_text(root)
        if redirect is not None:
            for check in checks:
                self._redirect_inconclusive(check, loc, root, redirect)
            return
        for check_id, judge, validate in HEADER_POLICIES:
            check = CHECKS[check_id]
            deficient, observed = judge(root.response.headers, root.response.text)
            if not deficient:
                self._clear(check, loc)
                continue
            self._emit(
                check,
                loc,
                test=root,
                control=probe,
                description=f"{root.response.url}: {observed}",
                validation=(self._validate_on_probe(judge, probe, test=root) if validate else None),
            )

    # --- shared helpers (Task 11 reuses these) ------------------------------

    def _https_ok(self) -> bool:
        f = self.obs.https_root
        return (
            f.usable
            and f.response is not None
            and f.response.status_code < 500
            and f.final_scheme == "https"
        )

    def _https_problem(self) -> tuple[str, str]:
        f = self.obs.https_root
        if f.usable and f.response is not None and f.response.status_code < 500:
            return (
                "blocked_prerequisite",
                f"{f.url} redirected to plain HTTP ({f.response.url}), so no HTTPS response's "
                "headers were observed",
            )
        return _why_unusable(f)

    def _usable(self, fetched: Fetched, checks: list[Check], location: str | None = None) -> bool:
        if fetched.usable and fetched.response is not None and fetched.response.status_code < 500:
            return True
        reason, text = _why_unusable(fetched)
        for check in checks:
            self._inconclusive(
                check, location or self.obs.root_path, fetched, text + ".", reason=reason
            )
        return False

    def _control_usable(self, control: Fetched, test: Fetched) -> bool:
        """A second observation proves something only if it is a readable response
        from the same origin (scheme, host, port) at a distinct path or query:
        never the test response re-read, never another origin's policy."""
        if not control.usable or control.response is None or test.response is None:
            return False
        if control.response.status_code >= 500:
            return False
        a, b = _normalised(control.response.url), _normalised(test.response.url)
        if a is None or b is None:
            return False
        same_origin = a[:3] == b[:3]
        # Distinct means another path: the same path with a query added (a login
        # or SPA bounce to "/?from=...") is the same resource re-read.
        distinct = a[3] != b[3]
        return same_origin and distinct

    def _validate_on_probe(
        self, judge: Judge, probe: Fetched, test: Fetched | None = None
    ) -> dict[str, Any]:
        if probe.response is None or not self._control_usable(probe, test or self.obs.root):
            return {"attempted": False, "outcome": "unavailable", "method": VALIDATION_METHOD}
        deficient, _ = judge(probe.response.headers, probe.response.text)
        return {
            "attempted": True,
            "outcome": "passed" if deficient else "failed",
            "method": VALIDATION_METHOD,
        }

    def _signal(
        self,
        check: Check,
        independence_class: str | None = None,
        likelihood_ratio: float | None = None,
        justification: str | None = None,
    ) -> Signal:
        return Signal(
            method=check.check_id.replace("-", "_"),
            prior=0.5,
            likelihood_ratio=likelihood_ratio or check.likelihood_ratio,
            independence_class=independence_class or check.independence_class,
            prior_justification=justification or check.justification,
        )

    def _edge_note(self, check: Check) -> str:
        note = ""
        https = self.obs.https_root
        if (
            check.check_id in POLICY_IDS
            and https.response is not None
            and https.final_scheme != "https"
        ):
            note = (
                " HTTPS redirected to plain HTTP, so this was judged on the plain-HTTP "
                "response that was actually served."
            )
        if self.edge and check.check_id in HEADER_FAMILY:
            note += (
                f" Served through {self.edge}: the edge may add or strip headers, so this "
                "describes what visitors receive, not necessarily what the origin sends."
            )
        return note

    def _emit(
        self,
        check: Check,
        location: str,
        *,
        test: Fetched,
        control: Fetched,
        description: str,
        validation: dict[str, Any] | None = None,
        signals: list[Signal] | None = None,
        version_only: bool = False,
        instance_key: str | None = None,
        references: list[str] | None = None,
    ) -> None:
        """Descriptions built from text already redacted (an excerpt, a capped list)
        are redacted again here and again in `Finding`: safe, because running
        core's redactor twice is the same as once and its markers are inert
        (ADR-028 clause 7). This replaces the `pre_redacted` path of web v1.0.3,
        which existed because the scanner-side strip read its own marker as an
        unterminated block."""
        location = _safe_location(location)
        result = self.engine.combine(signals or [self._signal(check)], version_only=version_only)
        evidence = [
            capture_http_pair(
                label=f"{check.check_id} at {location}",
                control_request=_request(control),
                control_response=_raw(control),
                test_request=_request(test),
                test_response=_raw(test),
                delta={"test": test.label, "control": control.label},
            )
        ]
        description = description.rstrip(".") + "."
        if validation and validation.get("method") == VALIDATION_METHOD:
            notes = (
                REDIRECT_NOTES
                if check.check_id == "web-https-redirect-missing"
                else VALIDATION_NOTES
            )
            description += notes.get(str(validation.get("outcome")), "")
        now = datetime.now(UTC)
        self.findings.append(
            Finding.create(
                org_id=self.ctx.org_id,
                scanner=self.scanner.name,
                scanner_version=self.scanner.version,
                check_id=check.check_id,
                title=check.title,
                target=self.target,
                location=location,
                instance_key=instance_key,
                severity=check.severity,
                confidence=result.confidence,
                confidence_provisional=result.provisional,
                detection_methods=result.detection_methods,
                validation=validation or {"attempted": False, "outcome": "not_applicable"},
                evidence=evidence,
                description=_redacted(description + self._edge_note(check)),
                impact=check.impact,
                remediation=check.remediation,
                references=references or [],
                taxonomy={},
                first_seen=now,
                first_seen_scan_id=self.ctx.scan_id,
                last_seen=now,
                last_seen_scan_id=self.ctx.scan_id,
                cost=self.ctx.cost.snapshot(),
            )
        )
        self.checks.append(CheckRun(check_id=check.check_id, location=location, outcome="reported"))

    def _redirect_inconclusive(
        self, check: Check, location: str, fetched: Fetched, description: str
    ) -> None:
        self._inconclusive(
            check,
            location,
            fetched,
            description,
            reason="blocked_prerequisite",
            impact="Unknown until the page the redirect leads to is scanned.",
            remediation=REDIRECT_REMEDIATION,
            note="the response is a redirect, not a page; test and control are the same response",
        )

    def _inconclusive(
        self,
        check: Check,
        location: str,
        fetched: Fetched,
        description: str,
        *,
        reason: str,
        impact: str = "Unknown until the request succeeds.",
        remediation: str = (
            "Re-run the scan. A persistent failure means the site is unreachable "
            "from the scanner, or an edge is blocking it."
        ),
        note: str = "no usable response; test and control are the same failed request",
    ) -> None:
        location = _safe_location(location)
        result = self.engine.combine(
            [
                self._signal(
                    check,
                    likelihood_ratio=1.0,
                    justification=(
                        "the request produced no usable answer, so nothing moves the prior"
                    ),
                )
            ]
        )
        raw = _raw(fetched)
        evidence = [
            capture_http_pair(
                label=f"{check.check_id} at {location}",
                control_request=_request(fetched),
                control_response=raw,
                test_request=_request(fetched),
                test_response=raw,
                delta={"note": note},
            )
        ]
        now = datetime.now(UTC)
        self.findings.append(
            Finding.create(
                org_id=self.ctx.org_id,
                scanner=self.scanner.name,
                scanner_version=self.scanner.version,
                check_id=check.check_id,
                title=check.title,
                target=self.target,
                location=location,
                severity=check.severity,
                confidence=result.confidence,
                confidence_provisional=result.provisional,
                no_verdict_reason=reason if reason in NO_VERDICT else "blocked_prerequisite",
                detection_methods=result.detection_methods,
                validation={"attempted": False, "outcome": "unavailable"},
                evidence=evidence,
                description=_redacted(description),
                impact=impact,
                remediation=remediation,
                references=[],
                taxonomy={},
                first_seen=now,
                first_seen_scan_id=self.ctx.scan_id,
                last_seen=now,
                last_seen_scan_id=self.ctx.scan_id,
                cost=self.ctx.cost.snapshot(),
            )
        )
        self.checks.append(
            CheckRun(check_id=check.check_id, location=location, outcome="inconclusive")
        )

    def _clear(self, check: Check, location: str) -> None:
        location = _safe_location(location)
        self.checks.append(CheckRun(check_id=check.check_id, location=location, outcome="clear"))

    # --- page content --------------------------------------------------------

    def _check_page_content(self) -> None:
        loc, root, probe = self.obs.root_path, self.obs.root, self.obs.probe
        mixed = CHECKS["web-mixed-content"]
        rest = [
            CHECKS[c]
            for c in (
                "web-sri-missing",
                "web-version-disclosure",
                "web-technology",
                "web-component-eol",
            )
        ]
        https_ok = self._https_ok()
        if not https_ok:
            reason, text = self._https_problem()
            self._inconclusive(
                mixed,
                loc,
                self.obs.https_root,
                f"HTTPS could not be read ({text}), so there is no HTTPS page "
                "whose subresources could be mixed content.",
                reason=reason,
            )
        if not self._usable(root, ([mixed] if https_ok else []) + rest):
            return
        assert root.response is not None
        page, page_url = self.obs.page, self.obs.page_url
        sri = CHECKS["web-sri-missing"]
        redirect = _redirect_text(root)
        if redirect is not None:  # no page was rendered, so no page content was read
            for c in ([mixed] if https_ok else []) + [sri]:
                self._redirect_inconclusive(c, loc, root, redirect)
        else:
            self._judge_page(root, probe, page, page_url, https_ok=https_ok)
        self._judge_server_identity(root, probe, page)

    def _judge_page(
        self,
        root: Fetched,
        probe: Fetched,
        page: html.PageFacts | None,
        page_url: str | None,
        *,
        https_ok: bool,
    ) -> None:
        loc, mixed, sri = self.obs.root_path, CHECKS["web-mixed-content"], CHECKS["web-sri-missing"]
        assert root.response is not None
        if https_ok:
            insecure = (
                []
                if page is None
                else (
                    [s.src for s in page.scripts if s.src.lower().startswith("http://")]
                    + [u for u in page.stylesheets if u.lower().startswith("http://")]
                )
            )
            if insecure:
                self._emit(
                    mixed,
                    loc,
                    test=root,
                    control=probe,
                    description=(
                        f"{root.response.url} is served over HTTPS but loads "
                        f"{len(insecure)} script/stylesheet URL(s) over plain "
                        f"HTTP: {', '.join(insecure)}"
                    ),
                )
            else:
                self._clear(mixed, loc)

        unpinned = (
            []
            if page is None or page_url is None
            else [
                s.src
                for s in page.scripts
                if not s.integrity and not html.is_same_origin(s.src, page_url)
            ]
        )
        if unpinned:
            self._emit(
                sri,
                loc,
                test=root,
                control=probe,
                description=(
                    f"{root.response.url} loads {len(unpinned)} cross-origin "
                    f"script(s) with no integrity attribute: {', '.join(unpinned)}"
                ),
            )
        else:
            self._clear(sri, loc)

    def _judge_server_identity(
        self, root: Fetched, probe: Fetched, page: html.PageFacts | None
    ) -> None:
        """Version, technology and EOL are facts about the server, true on a 3xx too."""
        loc = self.obs.root_path
        assert root.response is not None
        version = CHECKS["web-version-disclosure"]
        found = disclosure.version_disclosures(
            root.response.headers, page.generator if page else None
        )
        if found:
            cls = HTTP_HEADER if any(src != "meta generator" for src, _ in found) else HTML_DOCUMENT
            self._emit(
                version,
                loc,
                test=root,
                control=probe,
                signals=[self._signal(version, cls)],
                description="; ".join(f"{src}: {value}" for src, value in found),
            )
        else:
            self._clear(version, loc)

        tech = CHECKS["web-technology"]
        if self.detections:
            listed = "; ".join(
                f"{d.name}{' ' + d.version if d.version else ''} ({d.category}, from {d.evidence})"
                for d in self.detections
            )
            self._emit(tech, loc, test=root, control=probe, description=f"Identified: {listed}")
        else:
            self._clear(tech, loc)

        eol_check = CHECKS["web-component-eol"]
        matched = False
        for d in self.detections:
            entry = eol.match(self.eol_entries, d.name, d.version) if d.version else None
            if entry is None:
                continue
            matched = True
            self._emit(
                eol_check,
                loc,
                test=root,
                control=probe,
                signals=[self._signal(eol_check, VERSION_STRING)],
                version_only=True,
                instance_key=f"{entry.product}:{entry.branch}",
                references=[entry.source],
                description=(
                    f"{d.name} {d.version} was identified from {d.evidence}. The "
                    f"{entry.product} {entry.branch} branch reached vendor end-of-life on "
                    f"{entry.eol_date.isoformat()}. This rests on a version string "
                    "alone: distributions backport fixes without changing the version, "
                    "so this is a lead to verify, not proof of a vulnerability"
                ),
            )
        if not matched:
            self._clear(eol_check, loc)

    def _check_secrets(self) -> None:
        check = CHECKS["web-secret-in-response"]
        fetched = self.obs.same_origin_fetches()
        if not fetched:
            reason, text = _why_unusable(self.obs.root)
            self._inconclusive(check, self.obs.root_path, self.obs.root, text + ".", reason=reason)
            return
        any_found = False
        for f in fetched:
            assert f.response is not None
            kinds = disclosure.secret_kinds(f.response.captured.get("redactions", []))
            if not kinds:
                continue
            any_found = True
            control = self.obs.probe if f is self.obs.root else self.obs.root
            self._emit(
                check,
                f.path,
                test=f,
                control=control,
                description=(
                    f"The response for {f.url} contained text matching the "
                    f"credential pattern(s) {', '.join(kinds)}. The value was "
                    "redacted when captured and is not stored; the evidence "
                    "shows where it was found"
                ),
            )
        if not any_found:
            self._clear(check, self.obs.root_path)

    # --- error pages -----------------------------------------------------------

    def _check_error_pages(self) -> None:
        debug, error = CHECKS["web-debug-mode"], CHECKS["web-error-disclosure"]
        probe, loc, root = self.obs.probe, self.obs.probe_path, self.obs.root
        if probe.response is None or probe.failure is not None:
            reason, text = _why_unusable(probe)
            for c in (debug, error):
                self._inconclusive(c, loc, probe, text + ".", reason=reason)
            return
        if not root.usable or root.response is None or root.response.status_code >= 500:
            reason, text = _why_unusable(root)
            for c in (debug, error):
                self._inconclusive(
                    c,
                    loc,
                    root,
                    f"The homepage, the control that shows a trace is not site-wide content, "
                    f"could not be read: {text}.",
                    reason=reason,
                )
            return
        sig = disclosure.error_signature(probe.response.text)
        if sig is None:
            self._clear(debug, loc)
            self._clear(error, loc)
            return
        if root.response is not None:
            on_root = disclosure.error_signature(root.response.text)
            if on_root is not None and on_root.name == sig.name:
                if sig.kind == "error":
                    self._clear(debug, loc)
                    targets = (error,)
                else:
                    self._clear(error, loc)
                    targets = (debug,)
                for c in targets:
                    self._inconclusive(
                        c,
                        loc,
                        probe,
                        (
                            f"The same {sig.name} signature appears on the homepage, so it may be "
                            "ordinary site content rather than an error page."
                        ),
                        reason="ambiguous_response",
                    )
                return
        fired, other = (debug, error) if sig.kind == "debug" else (error, debug)
        self._emit(
            fired,
            loc,
            test=probe,
            control=root,
            references=[sig.source],
            description=(
                f"A request for a path that does not exist ({_redacted(probe.url)}) "
                f"returned HTTP {probe.response.status_code} with a {sig.name}: "
                f'"{_one_line(disclosure.excerpt(_redacted(probe.response.text), sig))}"'
            ),
        )
        self._clear(other, loc)

    # --- directory listings ------------------------------------------------------

    def _check_listings(self) -> None:
        check = CHECKS["web-directory-listing"]
        root, page, page_url = self.obs.root, self.obs.page, self.obs.page_url
        linked = html.linked_files(page, page_url) if page and page_url else {}
        for f in (root, *self.obs.directories):
            loc = f.path
            if f.response is None or f.failure is not None or f.response.status_code >= 500:
                reason, text = _why_unusable(f)
                self._inconclusive(check, loc, f, text + ".", reason=reason)
                continue
            found = listing.detect(f.response.text) if f.response.status_code == 200 else None
            if found is None:
                self._clear(check, loc)
                continue
            signals = [self._signal(check)]
            corroborated = (
                sorted(found.entries & linked.get(loc, frozenset())) if f is not root else []
            )
            if corroborated:
                signals.append(
                    self._signal(
                        check,
                        HTML_DOCUMENT,
                        likelihood_ratio=5.0,
                        justification=(
                            "a file the homepage itself links appears in the listing - a "
                            "second document agreeing with the first"
                        ),
                    )
                )
            note = (
                f" It includes {', '.join(corroborated)}, which the homepage links to."
                if corroborated
                else ""
            )
            self._emit(
                check,
                loc,
                test=f,
                control=self.obs.probe,
                signals=signals,
                description=(
                    f"{f.url} returns a generated directory listing "
                    f"({found.kind}) of {len(found.entries)} entr"
                    f"{'y' if len(found.entries) == 1 else 'ies'}.{note}"
                ),
            )

    # --- inventory ---------------------------------------------------------------

    def _check_robots(self) -> None:
        check, f = CHECKS["web-robots-paths"], self.obs.robots
        if f.response is None or f.failure is not None or f.response.status_code >= 500:
            reason, text = _why_unusable(f)
            self._inconclusive(check, f.path, f, text + ".", reason=reason)
            return
        if f.response.status_code != 200:
            self._clear(check, f.path)
            return
        disallowed, sitemaps = _robots_entries(f.response.text)
        if not disallowed and not sitemaps:
            self._clear(check, f.path)
            return
        tail = ". These paths were not fetched."
        listed = (
            f"robots.txt disallows {_listed(disallowed, 'nothing')} and names "
            f"sitemaps {_listed(sitemaps, 'none')}"
        )
        self._emit(
            check,
            f.path,
            test=f,
            control=self.obs.probe,
            description=_capped(listed, DESCRIPTION_CAP - len(tail)) + tail,
        )

    def _check_security_txt(self) -> None:
        check, f = CHECKS["web-security-txt-missing"], self.obs.security_txt
        if f.response is None or f.failure is not None or f.response.status_code >= 500:
            reason, text = _why_unusable(f)
            self._inconclusive(check, f.path, f, text + ".", reason=reason)
            return
        if f.response.status_code == 200 and re.search(r"(?im)^contact:", f.response.text):
            self._clear(check, f.path)
            return
        self._emit(
            check,
            f.path,
            test=f,
            control=self.obs.root,
            description=(
                f"{f.url} answered HTTP {f.response.status_code} without an RFC 9116 Contact field"
            ),
        )


def _safe_location(location: str) -> str:
    return redact_body(location)[0] or location


def _redacted(text: str) -> str:
    """Text built here for a description is redacted before it is cut or quoted.

    core's redactor (ADR-028) does the work; it used to live here, as a
    scanner-side workaround for D21, and was moved to core so every scanner
    gets it."""
    return redact_text(text)[0] or ""


def _capped(text: str, cap: int) -> str:
    """Redact, then cut to at most `cap` characters - never the other way round
    (core's `cap_prefix`, ADR-028 clause 4)."""
    return cap_prefix(text, cap)


def _listed(items: list[str], empty: str) -> str:
    if not items:
        return empty
    shown = ", ".join(f'"{i}"' for i in items[:ROBOTS_LISTED])
    more = len(items) - ROBOTS_LISTED
    return shown + (f" and {more} more" if more > 0 else "")


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _robots_entries(text: str) -> tuple[list[str], list[str]]:
    """Disallow paths and Sitemap URLs, in order, deduplicated. Split on the
    first colon only, so a Sitemap URL keeps its own "https://"."""
    disallowed: list[str] = []
    sitemaps: list[str] = []
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow":
            value = value.split("#", 1)[0].strip()
            if value and value not in disallowed:
                disallowed.append(value)
        elif key == "sitemap" and value and value not in sitemaps:
            sitemaps.append(value)
    return disallowed, sitemaps
