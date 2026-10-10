# web (Tool 4a) — live verification, 2026-10-07

ADR-017 live run of `web` v1.0.0 (Light) against 13 hosts approved by the operator: three of the operator's own domains, three well-configured public references, and seven public test sites published by their owners for scanner testing. No local lab target was used: they are ours, so circular, and Observatory cannot reach `127.0.0.1`.

Scans ran 2026-10-07T11:42:59Z–11:45:40Z UTC, one Light scan per host. **Every `confirmed` / `highly_likely` claim below was hand-verified** against an independent `curl` capture (headers of `https://H/`, `http://H/` and the scanner's own 404 probe path, plus the four <operator domain A> directory URLs). The disagreement analysis against Mozilla Observatory is in [crosscheck.md](crosscheck.md).

**Result: zero false positives across 13 real hosts.**

| Host | Our claims (confirmed / highly_likely) | Suspected | Inconclusive | Observatory | Hand verification |
|---|---|---|---|---|---|
| <operator domain A> (operator) | hsts-missing, csp-missing, clickjacking-unprotected, xcto-missing; **directory-listing ×4** (`/css/`, `/fonts/`, `/images/`, `/js/`) | — | 0 | D (30) | All true. curl: none of HSTS/CSP/XFO/XCTO on `/` or the 404 probe; `/css/ /fonts/ /images/ /js/` each return HTTP 200 Apache "Index of" with 9 / 65 / 292 / 15 entries — exactly the scanner's counts |
| <operator domain B> (operator) | hsts-missing, csp-missing, clickjacking-unprotected, xcto-missing (judged on `www.<operator domain B>`, the in-scope redirect target) | — | 0 | D (30) | All true; Observatory fails the same four |
| <operator domain C> (operator) | — | — | 20 / 20 (`ambiguous_response`) | unavailable | Correct: HTTPS answers **Cloudflare 525** (TLS handshake to origin failing); Observatory's scan failed on the same 525 |
| mozilla.org | csp-weak | — | 0 | B+ (80) | True: recorded `script-src 'self' 'unsafe-eval' 'unsafe-inline' …`; Observatory: `csp-implemented-with-unsafe-inline` |
| github.com | — | sri-missing (8 cross-origin scripts, no `integrity`) | 0 | A+ (115) | Agrees with Observatory's only failure (`sri-not-implemented-but-external-scripts-loaded-securely`, −5); no csp-weak because GitHub's `'unsafe-inline'` is in `style-src` only — Observatory agrees |
| example.com | https-redirect-missing, hsts-missing, csp-missing, clickjacking-unprotected, xcto-missing | — | 0 | F (10) | All true (`http://example.com/` answers 200; no headers); Observatory fails the same five |
| testphp.vulnweb.com | — | — | 21 / 21 (`timeout`) | "site seems to be down" | Correct: host unreachable (all curls time out); retried once 2026-10-07T11:55:56Z, still down. **Its PHP / Apache fingerprints and EOL rows are unexercised** |
| testasp.vulnweb.com | csp-missing, clickjacking-unprotected, xcto-missing (over HTTP) | version-disclosure; **component-eol: Microsoft-IIS 8.5** | 4 | F (0) | True: `Server: Microsoft-IIS/8.5`, `X-Powered-By: ASP.NET`; 443 times out |
| testaspnet.vulnweb.com | csp-missing, clickjacking-unprotected, xcto-missing | version-disclosure; **component-eol: Microsoft-IIS 8.5** | 4 | F (0) | True: `Server: Microsoft-IIS/8.5`, `X-AspNet-Version: 2.0.50727`. **No EOL claim for ASP.NET 2.0.50727 — correct:** that runtime string is also reported by .NET Framework 3.5 SP1, which is still supported |
| rest.vulnweb.com | csp-missing, clickjacking-unprotected, xcto-missing | version-disclosure; **component-eol: PHP 7.1** | 4 | F (10) | True: `X-Powered-By: PHP/7.1.26`, `Server: Apache/2.4.25 (Debian)`. No EOL claim for Apache 2.4 — correct: a supported branch; we make no CVE claims (spec §1) |
| httpforever.com | — | — | 4 | C+ (60) | Correct: its HTTP headers are good (Observatory agrees); HTTPS fails the TLS handshake |
| expired.badssl.com | — | — | 21 / 21 | F (10) | Inconclusive is correct (see crosscheck.md §2) — but the description did not say why; fixed in `web` 1.0.1 |
| self-signed.badssl.com | — | — | 21 / 21 | D (30) | As above |

**Fingerprint / EOL coverage exercised live:** Microsoft-IIS 8.5 EOL (two hosts), PHP 7.1 EOL, ASP.NET, Apache httpd, Cloudflare, Fastly, nginx. Not exercised: PHP 5.x (testphp down), Drupal, Joomla, WordPress, Bootstrap, AngularJS, jQuery.

**Request counts above the declared 12** (mozilla.org 23, <operator domain B> 18, <operator domain A> 13) are in-scope redirect hops followed by `core`'s HTTP client — ledger D26 (required before beta).

## Evidence

Raw evidence (scan JSON, recorded traffic, curl captures, Observatory JSON) is kept **outside git** — see the note at the end of crosscheck.md for why and where.
