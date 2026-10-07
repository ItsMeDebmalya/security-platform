"""The Web scanner — the Website Scanner's Light mode (Tool 4a).

Passive and bounded: `fetch.gather` makes at most 12 ordinary GETs once; this
module only judges what came back. Design: docs/superpowers/specs/
2026-10-02-web-light-design.md.

- A header claim is validated by re-reading the policy on the 404 control.
  That shows the policy is origin-wide, not one route's quirk. It does NOT show
  independent infrastructure - both responses come through the same edge.
- A response we could not read is inconclusive, never clear.
- State is derived by core/state.py through Finding.create, never set here.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.evidence import capture_http_pair
from core.http import HttpClient
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner
from scanners.web import csp, eol, fingerprint, headers, html
from scanners.web.checks import CHECKS, Check
from scanners.web.checks import requires_authorisation as _requires_authorisation
from scanners.web.fetch import Fetched, gather

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

Judge = Callable[[dict[str, str], str], tuple[bool, str]]
"""(headers, body) -> (deficient?, what was observed, quoted)."""


@register
class WebScanner(BaseScanner):
    name = "web"
    version = "1.0.0"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain", "url"})

    def requires_authorisation(self, mode: Mode) -> bool:
        return _requires_authorisation(mode)

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        http = ctx.http
        assert isinstance(http, HttpClient), "web needs an HTTP client from the context"
        return _Scan(self, target, mode, ctx, http).execute()


# --- judges: pure functions over (headers, body) -----------------------------


def _q(value: str | None) -> str:
    return "absent" if value is None else repr(value)


def _meta_csp(body: str) -> tuple[str, ...]:
    return html.extract(body, "about:blank").meta_csp if body else ()


def _csp_missing(h: dict[str, str], body: str) -> tuple[bool, str]:
    header = headers.get(h, "content-security-policy")
    meta = _meta_csp(body)
    return (
        header is None and not meta,
        f"Content-Security-Policy header {_q(header)}, <meta> policies {list(meta)!r}",
    )


def _csp_weak(h: dict[str, str], body: str) -> tuple[bool, str]:
    header = headers.get(h, "content-security-policy")
    meta = _meta_csp(body)
    policies = csp.parse(header)
    for value in meta:
        policies.extend(csp.parse(value))
    if not policies:
        return False, "no policy"
    received = f"Content-Security-Policy header {_q(header)}, <meta> policies {list(meta)!r}"
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
        return reason, f"{f.url} could not be fetched ({f.failure or 'not requested'})"
    return "ambiguous_response", (
        f"{f.url} answered HTTP {f.response.status_code}, a server "
        "error, so it may not reflect the site's configuration"
    )


def _request(f: Fetched) -> dict[str, Any]:
    return {"method": "GET", "url": f.url}


def _raw(f: Fetched) -> dict[str, Any]:
    if f.response is None:
        return {"status": 0, "headers": {}, "body": None, "elapsed_ms": 0}
    return {
        "status": f.response.status_code,
        "headers": dict(f.response.headers),
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
        # Task 11 inserts the content, error-page, listing and inventory checks here.
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
        if not probe.usable or probe.response is None or probe.response.status_code >= 500:
            return {"attempted": False, "outcome": "unavailable", "method": VALIDATION_METHOD}
        redirected = probe.final_scheme == "https" or 300 <= probe.response.status_code < 400
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
            validation=self._validate_on_probe(judge, self.obs.https_probe),
        )
        self._clear(other, loc)

    # --- header policies ---------------------------------------------------

    def _check_header_policies(self) -> None:
        root, probe, loc = self.obs.root, self.obs.probe, self.obs.root_path
        checks = [CHECKS[c] for c, _, _ in HEADER_POLICIES]
        if not self._usable(root, checks):
            return
        assert root.response is not None
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
                validation=self._validate_on_probe(judge, probe) if validate else None,
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

    def _validate_on_probe(self, judge: Judge, probe: Fetched) -> dict[str, Any]:
        if not probe.usable or probe.response is None or probe.response.status_code >= 500:
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
        if self.edge and check.check_id in HEADER_FAMILY:
            return (
                f" Served through {self.edge}: the edge may add or strip headers, so this "
                "describes what visitors receive, not necessarily what the origin sends."
            )
        return ""

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
            description += VALIDATION_NOTES.get(str(validation.get("outcome")), "")
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
                description=description + self._edge_note(check),
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

    def _inconclusive(
        self, check: Check, location: str, fetched: Fetched, description: str, *, reason: str
    ) -> None:
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
                delta={"note": "no usable response; test and control are the same failed request"},
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
                description=description,
                impact="Unknown until the request succeeds.",
                remediation=(
                    "Re-run the scan. A persistent failure means the site is unreachable "
                    "from the scanner, or an edge is blocking it."
                ),
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
        self.checks.append(CheckRun(check_id=check.check_id, location=location, outcome="clear"))
