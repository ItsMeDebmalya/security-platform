# web (Tool 4a) — competitor cross-check, 2026-10-07

ADR-024 disagreement analysis for `web` v1.0.0 (Light) over the 13 hosts in [verification.md](verification.md). **Priority: false negatives** — anything a reference tool reports that we do not is a candidate blind spot, and each one is classified below as a real gap, out of our declared scope, or a difference of opinion we can defend.

## Method

- **Mozilla Observatory** — `POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=H`, then `GET …/api/v2/analyze?host=H` for per-test results (12 tests). Each test was mapped to our checks: CSP → csp-missing/csp-weak; redirection → https-redirect-missing; HSTS → hsts-missing/hsts-weak; Referrer-Policy → referrer-policy-*; SRI → sri-missing/mixed-content; X-Content-Type-Options → xcto-missing; X-Frame-Options → clickjacking-unprotected; CORS → cors-wildcard; cookies → deferred (D-W1); COEP/COOP/CORP → declined (spec §3.2).
- **Observatory `pass: null`** (score 0) means *not applicable* — e.g. `sri-not-implemented-but-all-scripts-loaded-from-secure-origin`. It is **not** a failure. (A first-pass collector counted it as one and produced three false "Observatory-only" SRI hits on codez.in, mozilla.org and example.com; caught before reporting.)
- **securityheaders.com was unavailable**: it answers automated clients (curl, with or without a browser User-Agent, and a fetch tool) with HTTP 403. Of the headers it grades, only `Permissions-Policy` is not also covered by Observatory; it is classified below from the spec instead.
- **Wappalyzer** was not run as a data source. Per ADR-024 its output may only ever be a coverage checklist, never seed our data; the fingerprint coverage question was answered by the vulnweb hosts instead (verification.md).

## False positives

**None.** No claim of ours was contradicted by curl or by Observatory on any host. Where both tools judged a host, every Observatory failure that maps to one of our checks was matched by a finding of ours (as a claim, or as an honest `inconclusive` when we could not read the response).

## False-negative candidates, classified

| # | Reference reports, we do not | Classification | Action |
|---|---|---|---|
| 1 | Session cookies without `Secure` on testasp / testaspnet (Observatory −40) | **Out of declared scope** — cookie checks are deferred as D-W1 because `core/` redacts `Set-Cookie` whole | Real-world evidence that D-W1 matters; unblocked by the `core/` redaction change (ledger D21) |
| 2 | Header verdicts (CSP / XFO / XCTO) on expired.badssl.com and self-signed.badssl.com — Observatory reads them through the invalid certificate | **Defensible difference of opinion**: a browser rejects that page, so headers served over a session that fails verification describe nothing a visitor receives; the certificate itself is the `tls` scanner's finding. **But the silence was a defect**: our findings said only "could not be fetched (blocked_prerequisite)" | **Fixed in `web` 1.0.1**: a failed request now carries its cause — e.g. "TLS certificate verification failed (certificate has expired)", "TLS handshake failed (…)", "connection timed out", "DNS lookup failed". Still `inconclusive`, now saying why. Re-verified live on 2026-10-07 (ADR-022 *close*): expired.badssl.com → "TLS certificate verification failed (certificate has expired)", self-signed.badssl.com → "(self-signed certificate)", httpforever.com → "TLS handshake failed (ssl/tls alert handshake failure)" |
| 3 | "No working HTTPS" on HTTP-only / TLS-broken sites (testasp, testaspnet, rest.vulnweb.com; httpforever.com) — Observatory fails HSTS ("no-https") and redirection | HSTS / redirect: **defensible by declaration** (spec §3.1 — never claim missing HSTS on a host with no HTTPS). The underlying fact, though, is stated definitively by **no** check of ours: a **real product-level gap** | **Deferred, HIGH PRIORITY for 4b/4c** (ledger D23). The hard part, recorded there: a timeout on 443 cannot separate "port filtered / unreachable" from "no HTTPS service" — an honest check needs a second signal |
| 4 | Weak HSTS on an apex redirect: `https://mozilla.org/` → 301 with `max-age=60`; we judged the final `www.` response (one year). Observatory also passed it | **Real gap, minor** — `core`'s HTTP client returns only the final response, so redirect-hop headers are invisible to every scanner | Ledger D24 (needs `core/` to expose the redirect chain) |
| 5 | `Permissions-Policy` (graded by securityheaders.com, not by Observatory) | **Declined, with the reason now in spec §3.2**: defence in depth that limits the damage of *another* flaw; its absence is not exploitable; there is no safe universal value to test against, so "missing" would fire on nearly every site and bury real findings (precision ≥ 0.95) | Spec §3.2 row added; revisit on a site-specific signal (third-party frames, sensitive feature use) |
| 6 | COEP / COOP / CORP | **Declined** (spec §3.2) | — |

## Restraint calls that held

- **ASP.NET 2.0.50727 — no end-of-life claim.** That runtime string is also what .NET Framework 3.5 SP1 reports, and 3.5 SP1 is supported; claiming EOL from it would have been a false positive.
- **Apache 2.4.25 — no claim beyond version disclosure.** A supported branch; Tool 4a makes no CVE claims (spec §1).
- **Unreachable / erroring hosts → all `inconclusive`** (testphp timeout, kinetrix.co.in Cloudflare 525, badssl certificate failures): never a guessed "clear".

## Other observations recorded in the ledger

- **D25 — cost metering ignores failed attempts.** testphp: 90 s of wall time, ~10 connection attempts, `telemetry.requests = 0`. Not cosmetic: a dead host looks free to rate limiting and, later, to billing.
- **D26 — the 12-GET cap is exceeded by redirect hops** (mozilla.org 23, kinetrix.in 18, codez.in 13). Declaration and behaviour disagree; required decision before beta.

## For the operator's own domains

- **codez.in**: four open directory listings exposing 381 files; no HSTS, CSP, X-Frame-Options or X-Content-Type-Options.
- **kinetrix.co.in**: effectively down over HTTPS — Cloudflare 525 (Cloudflare cannot complete a TLS handshake with the origin).

## Raw evidence

Kept out of git deliberately. The raw curl captures contain live session cookie values issued to the scanner (`ASP.NET_SessionId`, `ASPSESSIONID…`, GitHub's `_gh_sess` / `_octo` / `logged_in`) — `core` redacts `Set-Cookie` in recorded traffic, but curl output is raw — and the recorded traffic holds full page bodies from the operator's domains (including the 381-file directory listings). Disposition is the operator's decision; see the Task 13 report.
