# Web — Website Scanner, Light mode (Tool 4a) — Design

*Design spec. Working artifact for the implementation plan, not part of the canonical doc set
(`SPEC.md` / ADRs / roadmap remain authoritative — this feeds changes into them, it does not
replace them). Date: 2026-10-02. Stage 0 of [docs/20-migration-runbook.md](../../20-migration-runbook.md).*

Scanner name: **`web`**. Directory: `scanners/web/`.

---

## 1. What this is, and what was settled before writing it

Tool 4 is SPEC **A1, Light mode** — the reconnaissance half of the Website Scanner. Its scope in
[05-phase-1-first-tools.md](../../05-phase-1-first-tools.md) has two halves; they are built as two
consecutive specs:

- **Tool 4a — this spec.** The commodity half: transport security, security headers, CSP quality,
  information disclosure, directory listing, technology fingerprint, end-of-life components,
  robots/sitemap/security.txt.
- **Tool 4b — next spec.** AI and agent exposure (MCP servers, agent panels, model endpoints). Split
  out because its probes sit on the line "finding an exposed server is passive, reading what is on
  it is not" and on non-standard ports; each probe needs its own passivity ruling, likely an ADR.
  Whether 4b's checks join `web` or form their own scanner is decided in 4b's spec.

**Phase 1 closes when 4a and 4b have both shipped and the merged `scan all` command (its own small
change, after 4b) exists.** This spec does not close Phase 1 by itself.

Decisions taken with the operator during design (2026-10-02):

| Decision | Choice | Why |
|---|---|---|
| Cookie-flag checks | **Deferred** (D-W1) | `core/evidence.py` redacts the whole `Set-Cookie` value, attributes included, and the recording backend stores that redacted capture as the fixture, so replay can never see a flag. `dict(response.headers)` also folds repeated `Set-Cookie` headers into one ambiguous string. Fixing it needs an additive `core/` change touching secret redaction; that deserves its own reviewed change, and this task keeps `core/` import-only. |
| AI exposure | **Split to 4b** | See above. |
| Outdated components | **Curated EOL table** | A sourced, dated table of branches past vendor end-of-life. No CVE claims in 4a — CVE matching without distro/backport awareness is the false-positive generator the plan warns about. |
| `scan all` | **After 4b, own change** | Built once, against the final four-tool set. |
| Approach | **Gather first, then judge** | A fixed, bounded request plan, pure analyzer modules, fingerprints as data. Not a crawler (that is Standard's JS-rendered crawl) and not a template DSL (YAGNI). |
| Name | **`web`** | Finding IDs hash the scanner name; Standard extends this same scanner later (modes are additive), so a Light-specific name would force a `renamed_from` migration. |

---

## 2. Request plan — bounded, ordinary, passive

At most **12** scanner-issued GETs per run (in-scope redirect hops are additional — ledger D26), all through `ctx.http`, `ctx.check_alive()` before each:

| # | Request | Purpose |
|---|---|---|
| 1 | `https://<host>/` | the primary observation |
| 2 | `http://<host>/` | does plain HTTP redirect to HTTPS? |
| 3 | `https://<host>/sp-404-probe-<sha256(host)[:16]>` | **the control**: a path that cannot exist. Its 404 is also the error-page probe and the second same-origin response used for validation (§5). Deterministic, not random (amended 2026-10-07): a random path would never match a recorded fixture, so replay (0b.4) and the corpus need the same path on every run; 16 hex of a hash is still a path no site serves |
| 4 | `http://<host>/<same probe path>` | validation for the redirect check |
| 5 | `/robots.txt` | robots review |
| 6–7 | up to 2 `Sitemap:` URLs named in robots.txt, same host only | sitemap review |
| 8 | `/.well-known/security.txt` | RFC 9116 presence |
| 9–12 | up to 4 directory candidates | **only** parent directories of same-origin assets the homepage itself links (`/static/`, `/assets/js/`) |

Rules:

- **We never guess paths.** `/.env`, `/.git/`, `/admin`, backup filenames — that is content
  discovery, SPEC A1 Standard ("hidden file/dir discovery"), and is out of 4a.
- `<host>` comes from the target: a `domain` target `example.com` means `https://example.com/`; a
  `url` target uses its scheme/host/port, and its path replaces `/` in request 1.
- Redirects are followed **in scope only** — `HttpClient` already declines an off-scope hop and
  returns the redirect itself, which is a reportable fact, not an error.
- `service_hosts` is empty: this scanner talks to the target only.
- Every check is **passive** under ADR-023 (ordinary GETs a browser would make, no malformed
  input, nothing state-changing), so `requires_authorisation()` returns `False` in every mode —
  declared per check, not inferred from the mode.
- A failed request (timeout, connection refused, 429, 5xx) is recorded in the observation set, never
  raised; the checks that depend on it go `inconclusive` (§5.4).

---

## 3. Check catalogue

Severity is "how bad if true", never adjusted for certainty. `location` is the exact path the
claim was observed on (`"/"` for the root response), never `"$"` for an HTTP observation.

| check_id | Severity | Fires when |
|---|---|---|
| `web-https-redirect-missing` | medium | `http://` serves content (2xx) instead of redirecting to `https://`, **and** HTTPS is available |
| `web-hsts-missing` | medium | HTTPS response has no `Strict-Transport-Security` |
| `web-hsts-weak` | low | HSTS `max-age` < 15768000 (6 months) |
| `web-csp-missing` | medium | no `Content-Security-Policy` header **and** no `<meta http-equiv="Content-Security-Policy">` |
| `web-csp-weak` | medium | the effective script policy (`script-src`, falling back to `default-src`) allows `'unsafe-inline'` without a nonce/hash, `'unsafe-eval'`, `*`, or the `http:`/`data:` schemes |
| `web-clickjacking-unprotected` | medium | no `X-Frame-Options` **and** no CSP `frame-ancestors` (meta CSP cannot set `frame-ancestors`, so only the header counts) |
| `web-xcto-missing` | low | no `X-Content-Type-Options: nosniff` |
| `web-referrer-policy-unsafe` | low | explicitly `unsafe-url` or `no-referrer-when-downgrade` |
| `web-referrer-policy-missing` | info | header absent — `info` because browsers have defaulted to `strict-origin-when-cross-origin` since 2020-21 |
| `web-cors-wildcard` | low | root response sends `Access-Control-Allow-Origin: *` |
| `web-mixed-content` | low | the HTTPS page references `http://` scripts or stylesheets. **Low**, not medium: current browsers block mixed active content, so the impact is a broken page, not interception |
| `web-sri-missing` | low | a cross-origin `<script src>` has no `integrity` attribute |
| `web-version-disclosure` | low | `Server`, `X-Powered-By`, `X-AspNet-Version` or `<meta name="generator">` exposes a version number |
| `web-error-disclosure` | medium | the 404 control body carries a stack trace / framework error signature |
| `web-debug-mode` | high | the 404 control body is an interactive debugger page (Werkzeug debugger, Laravel Ignition, Django `DEBUG=True` technical 404) |
| `web-secret-in-response` | high | `core`'s own capture redaction hit a secret pattern (`aws_access_key_id`, `github_token`, `slack_token`, `private_key`, `bearer_token`) in a same-origin body. `google_api_key` is **excluded**: browser keys are public by design |
| `web-directory-listing` | medium | a directory candidate returns an autoindex page (Apache, nginx, IIS, Python `http.server`) |
| `web-technology` | info | technologies (and versions where exposed) matched by the fingerprint DB — inventory |
| `web-robots-paths` | info | robots.txt `Disallow` entries and sitemap URLs — inventory; **never fetched** |
| `web-security-txt-missing` | info | no RFC 9116 `security.txt` |
| `web-component-eol` | medium | a fingerprinted component's version falls on a branch in the EOL table. Always `version_only=True` |

`info` findings are `informational` by `core/state.py` and excluded from precision/recall by
[10-measurement.md](../../10-measurement.md) — inventory is not a vulnerability (the domscout rule).

### 3.1 Cross-cutting rules

- **Challenge pages.** If the root response is an anti-bot interstitial (Cloudflare/Akamai/
  other challenge signatures in `challenge.py`), every content- or header-dependent check is
  `inconclusive` with `no_verdict_reason="waf_block"`. We never fingerprint a challenge page as the
  customer's stack.
- **CDN attribution.** A detected CDN/edge is named in every header finding's description: the edge
  can add or strip headers, so the finding describes what visitors receive, not necessarily what the
  origin sends.
- **No HTTPS.** If request 1 fails at the transport level, the HTTPS-dependent checks (`hsts-*`,
  `mixed-content`, and `https-redirect-missing`, whose control is the HTTPS response) are
  `inconclusive` — reason `timeout` when the failure was a timeout, `blocked_prerequisite` for any
  other transport failure (§5.5), and the description names the cause. We never report "missing
  HSTS" on a host that has no HTTPS — that is the `tls` scanner's territory.
- **Never put words in a target's mouth.** Descriptions quote the header value or body excerpt
  actually received, never a reconstructed string (ledger standing observation).

### 3.2 Declined or owed — recorded, not silently missing (ADR-024)

| Item | Status | Reason |
|---|---|---|
| Cookie `Secure`/`HttpOnly`/`SameSite` | **owed — D-W1** | needs the `core/` redaction change in §1 |
| Fingerprinting by cookie name | owed — D-W1 | same cause: `Set-Cookie` is redacted whole |
| CORP / COOP / COEP | declined | low value for a Light posture report; revisit on demand |
| HTML-comment heuristics beyond secret patterns | declined | too noisy for precision ≥ 0.95 |
| TLS summary | declined here | the `tls` scanner owns it; `scan all` merges them. A scanner never imports another (CLAUDE.md invariant) |
| Sensitive-path probing (`/.env`, `/.git/`) | Standard | content discovery, SPEC A1 Standard |
| `Permissions-Policy` | declined (2026-10-07, after live cross-check) | It limits which powerful browser features (camera, microphone, geolocation, payment, USB …) a page and the frames it embeds may use. That is defence in depth: it reduces the damage of *another* flaw (an XSS, a malicious third-party frame), and its absence is not itself exploitable. There is no safe universal value to test against — the right policy depends on which features the site actually uses — so "missing" would fire on almost every site and bury real findings, against precision ≥ 0.95. Mozilla Observatory does not score it either (securityheaders.com does). Revisit when there is a site-specific signal, e.g. the page embeds third-party frames or requests a sensitive feature |

---

## 4. Architecture

`scanners/web/`, following the domscout/email shape. Pure modules first, each unit-tested offline
before anything touches the network.

| Module | Does | Depends on |
|---|---|---|
| `checks.py` | the catalogue: `Check(check_id, title, severity, likelihood_ratio, justification, passive=True)` — no default for `passive`; independence-class constants; `requires_authorisation()` via `core.authz.checks_require_authorisation` | `core.authz` |
| `fetch.py` | executes §2's plan through `ctx.http`; returns a frozen `Observations` (one `Fetched` per request: the `CapturedResponse` or a failure reason) | `core.http` |
| `html.py` | stdlib `html.parser` extractor: `<script src integrity>`, stylesheets, `<meta http-equiv>` CSP, `<meta name="generator">`, same-origin asset paths | — |
| `headers.py` | HSTS / XFO / XCTO / Referrer-Policy / CORS parsing and judgement | — |
| `csp.py` | CSP parse into directives, `default-src` fallback, nonce/hash awareness, multiple policies (comma-joined, which `dict(headers)` produces and the CSP grammar permits) | — |
| `disclosure.py` | version-string extraction, error/debug signatures, secret hits read from the capture's `redactions` list | — |
| `listing.py` | autoindex signatures and listing-entry parsing | — |
| `challenge.py` | challenge-page and CDN detection | `fingerprint.py` data |
| `fingerprint.py` + `data/fingerprints.yaml` | technology detection from header, HTML and script-path patterns with optional version capture | — |
| `eol.py` + `data/eol.yaml` | EOL-branch matching | — |
| `scanner.py` | `WebScanner` (`name="web"`, `version="1.0.0"`, `supported_modes={"light"}`, `target_types={"domain","url"}`); `_Scan` gathers once, judges, emits via `Finding.create` | all of the above |

No new runtime dependency: HTML parsing is stdlib; YAML loading uses the PyYAML the repo already
depends on.

### 4.1 Data discipline

Every entry in `fingerprints.yaml` and `eol.yaml` carries `source` (vendor documentation, a vendor
EOL page, or "own observation: <target, date>") and `reviewed_on`. A data-integrity test enforces:

- both fields present and non-empty on every entry;
- **ADR-003 / SPEC A1 guardrail:** no entry sourced from Wappalyzer or its forks (their data is
  GPL-3.0). Signatures are authored from our own observation and public documentation;
- **freshness:** no entry's `reviewed_on` is older than `core.deprecation_calendar.STALE_AFTER_DAYS`
  (180), so a stale table fails CI rather than shipping;
- **EOL entries are past-only:** every `eol.yaml` entry's `eol_date` ≤ its `reviewed_on`. The table
  lists only branches *already* past end-of-life when the entry was written, so no entry ever changes
  status at runtime — a frozen corpus case cannot rot from "clear" to "reported" as dates pass
  (the domscout `domain-expiring` lesson). New EOLs are added as they happen, with review.

Freshness is a CI property, not a runtime one: suppressing stale entries at scan time would compare
against wall-clock today and rot the frozen corpus. (This revises the design conversation's
"suppressed at runtime", for exactly that reason.)

### 4.2 Boundaries

- `core/` is **import-only** — no edits.
- No import of any other scanner (enforced by `tests/architecture/`).
- No asset-graph writes. Sitemap URLs appear only in the `web-robots-paths` informational finding.
- `service_hosts` empty; nothing outside the target is contacted.

---

## 5. States, confidence, evidence

### 5.1 Independence classes

| Class | What it is |
|---|---|
| `http_header` | a response header as served |
| `html_document` | parsed markup of a same-origin page |
| `error_page` | the 404 control's body |
| `autoindex` | a directory-listing page |
| `version_string` | a version read from a header or markup — EOL only |

### 5.2 Validation — how header claims reach `confirmed`

Header-policy checks (`hsts-*`, `csp-missing`, `csp-weak`, `clickjacking-unprotected`,
`xcto-missing`, `referrer-policy-unsafe`, `cors-wildcard`) validate by **re-reading the policy on a
second, distinct same-origin response — the 404 control** (request 3):

| Control response | `Validation` | Effect |
|---|---|---|
| same deficiency present | `attempted=True, outcome="passed", method="second_same_origin_response"` | may reach `confirmed` (confidence ≥ 0.95) |
| header present / policy differs | `outcome="failed"` | confidence capped at 0.5 → `suspected`; description says the header is set per route |
| control unusable (failed, challenge) | `outcome="unavailable"` | `suspected` at most |

`web-https-redirect-missing` validates the same way against request 4.

**The limit, stated in the spec and in every such finding's validation record:** this shows the
policy is origin-wide rather than one route's quirk. It does **not** show independent
infrastructure — both responses traverse the same edge, so it shares that blind spot (ledger:
"a verifier that shares the blind spot confirms nothing"). The challenge-page rule (§3.1) covers
the largest shared failure mode.

### 5.3 The other routes

- `web-directory-listing` → **`highly_likely`** across two classes: the autoindex page
  (`autoindex`) **and** a file the homepage itself linked (`html_document`) appearing in that
  listing.
- Single-class, honestly **`suspected`**: `error-disclosure`, `debug-mode`, `secret-in-response`,
  `mixed-content`, `sri-missing`, `version-disclosure`, `component-eol` (also `version_only=True`,
  capped at 0.6 by `ConfidenceEngine`). These are excused from the precision count, on both sides.
- Priors and likelihood ratios are hand-assigned per check in `checks.py`, each with a one-line
  justification (how-to-add-a-scanner §0); all `confidence_provisional=True` until Phase 4.
- **State is never set by the scanner** — `Finding.create` derives it via `core/state.py`.

### 5.4 Evidence — a control-vs-test pair on every finding

All HTTP evidence through `capture_http_pair` (redacted, size-capped by `core`):

| Finding family | Test | Control |
|---|---|---|
| header policies | root response | 404 control response |
| `https-redirect-missing` | `http://` root | `https://` root (proves HTTPS existed, so a redirect was possible) |
| `directory-listing` | the directory response | the random-path 404 |
| `error-disclosure` / `debug-mode` | the 404 control | root page (proves the trace is not site-wide content) |
| `secret-in-response` | the body, carrying `[redacted]:<kind>` | root or 404, whichever is not the test. The secret itself is never stored — `core` redacted it at capture |
| `mixed-content` / `sri-missing` / `version-disclosure` / `component-eol` | the response carrying it | 404 control, or `control_rationale` where no natural control exists |
| `info` inventory | the observed response | `control_rationale` ("inventory, not a claim of weakness") |

An empty `control_rationale` is refused by the contract; none is left empty.

### 5.5 "We could not tell" — failure semantics

| Event | Result |
|---|---|
| challenge page on root | dependent checks `inconclusive`, `waf_block` |
| request timeout | dependent checks `inconclusive`, `timeout` |
| 429 | dependent checks `inconclusive`, `rate_limited` |
| HTTPS transport failure | HTTPS-dependent checks `inconclusive`: `timeout` if the failure was a timeout, otherwise `blocked_prerequisite`; the cause is named (certificate verification, handshake, timeout, DNS) |
| 5xx on root | header checks `inconclusive`, `ambiguous_response` |
| robots/sitemap/security.txt 404 | definite — "absent", not inconclusive |
| root ends on a 3xx (off-scope redirect declined, or an in-scope chain that exhausted `MAX_REDIRECTS`) | amended 2026-10-07: a redirect response is never rendered as a page, so the page-header checks (`csp-missing`, `csp-weak`, `clickjacking-unprotected`, `xcto-missing`, `referrer-policy-*`, `cors-wildcard`) and the page-content checks (`mixed-content`, `sri-missing`) are `inconclusive`, `blocked_prerequisite`, naming the redirect. HSTS (meaningful on an HTTPS 3xx) and the server-identity checks (`version-disclosure`, `technology`, `component-eol`) still judge it |

Every check appears in `telemetry.checks_run` with its outcome (`reported` / `clear` /
`inconclusive`) and location. Each source fails independently: robots.txt timing out does not make
the header checks unknown.

---

## 6. Testing and definition of done

### 6.1 Unit tests (offline, written first)

- Positive and negative test for every parser rule in `csp`, `headers`, `html`, `listing`,
  `disclosure`, `challenge`, `fingerprint`, `eol`.
- The data-integrity tests of §4.1.
- Scanner tests over `httpx.MockTransport`: every catalogue check appears in `checks_run`; `state`
  never hand-set; no request outside §2's plan; ≤ 12 scanner-issued requests (in-scope redirect hops are additional — ledger D26); `check_alive` honoured (a killed scan
  stops); `requires_authorisation()` is `False` for every mode.
- Existing `tests/architecture/` rules apply unchanged.

### 6.2 Frozen corpus

`corpus/targets/web.yaml`, `corpus/expected/web.yaml`, fixtures recorded by
`corpus/generators/web.py` through `RecordingHttpBackend` against a **local lab**:

- one nginx container with a server block per case, published on `127.0.0.1` ports;
- small Flask (Werkzeug debugger) and Django `DEBUG=True` containers — error and debug pages are
  recorded **from the real frameworks**, never hand-written HTML ("ground truth is code too");
- lab images registered in `tools/registry.yaml` with their licences, as Juice Shop and DVWA are
  (no runtime dependency is added; lab targets are registered).

Cases: a positive and a negative for every check; one **known-good** hardened site that must report
nothing beyond `informational` (anything else is an FP by definition); a challenge-page case (all
dependent checks `inconclusive`); an HTTPS-unavailable case; a timeout case.

**Stated limit:** this corpus is written by the scanner's author and encodes the same assumptions.
It proves regression, not correctness.

### 6.3 Gate

```yaml
gate:
  precision: 0.95
  recall: 0.85
  inconclusive_max: 0.15
  recall_definition: corpus_relative
```

The roadmap's numbers ([03-roadmap.md](../../03-roadmap.md) Tool 4 row). Published with its claim
count, always.

### 6.4 Live verification (ADR-017) — before "done"

Operator infrastructure (`codez.in`, `erp.codez.in`, `kinetrix.in`, `kinetrix.co.in`) plus a handful
of public sites (Light is passive — [13-test-targets.md](../../13-test-targets.md) §5). Every
finding hand-verified with `curl -sI` / `curl -s`. A live finding that turns out wrong becomes a
corpus case.

### 6.5 Competitor parity (ADR-024) — before "done"

Reference set: **Mozilla Observatory** and **securityheaders.com** for headers/redirects/CSP;
**Wappalyzer's output** as a fingerprint-coverage checklist only. A disagreement analysis like
domscout's: every competitor-only finding is chased as a candidate false negative; a check we decline
is recorded with its reason (§3.2). We read output and published methodology; we never seed checks
or fingerprint data from them (ADR-024 licence line). Recorded under `corpus/crosscheck/` and in the
ledger.

---

## 7. Docs reconciled as part of the work

- **SPEC A1** — Light status, the 4a/4b split, the cookie deferral. Fix the status table's
  "No Light-mode gate is set in the roadmap", which contradicts
  [03-roadmap.md](../../03-roadmap.md) line 77 (CLAUDE.md rule 4: fix the wrong one and say so).
- **03-roadmap.md** — split the Tool 4 row into 4a and 4b.
- **Ledger** — a Tool 4a entry (Built / Found & fixed / Decided / Deferred) and register items:
  **D-W1** cookie checks + cookie-name fingerprints (needs the `core/` redaction change);
  **D-W2** a live challenge-page positive if no operator-controlled CDN is available to record one;
  **D-W3** scheduled fingerprint/EOL re-review. Mark **D10/D19** (HSTS) as covered by `web-hsts-*`.
- **12-cli-runbook.md** — `scan run web` with real output. **13-test-targets.md** — the lab.
- No ADR change is expected. If one becomes necessary it is written and recorded in
  `docs/08-changelog.md`.

---

## 8. Out of scope

Tool 4b (AI exposure); `scan all`; cookie checks (D-W1); any `core/` edit; Standard-mode checks;
asset-graph contribution. Tool 3's owed items in the ledger's "Next" (`service_hosts` ADR, kinetrix
live runs, whole-branch review, PR) remain open and are not closed by this work.

## 9. Open items to settle during implementation

- **Challenge-page fixture.** Recording a real interstitial needs a CDN-fronted host we control in
  challenge mode. If none is available, the case is deferred as D-W2 rather than faked.
- **Severity of `web-cors-wildcard`.** `*` on a public, credential-less page is often intentional;
  low is the ceiling, and the description must say when it is benign. Revisit after live runs.
- **Exact signature strings** for challenge pages, autoindex and debug pages are taken from the
  recorded real responses, not written from memory.
