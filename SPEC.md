# SPEC — Build Specification

*The canonical, current-truth statement of WHAT we build and WHAT each tool must do.*

---

## What this document is, and is not

**This is the authority on WHAT to build.** It replaces [docs/reference/product-spec.md](docs/reference/product-spec.md) in that role — that file is the v2 catalogue, preserved verbatim as history, and is now a content source, not the authority.

This document is **not**:

- the schedule — that is [docs/03-roadmap.md](docs/03-roadmap.md);
- the decision record — that is [docs/02-decisions.md](docs/02-decisions.md);
- the strategy front door — that is [docs/18-v4-plan.md](docs/18-v4-plan.md);
- the build log — that is [docs/14-progress-ledger.md](docs/14-progress-ledger.md).

Where those documents own something, this one **links, does not restate**. Restating is how this document set has drifted apart before — see the ledger's repeated "a number reached a decision document without being checked against its primary source" defect (D13, D16). Do not repeat it here.

**If a change here alters a decision, update the ADR too** ([docs/02-decisions.md](docs/02-decisions.md)), and record it in [docs/08-changelog.md](docs/08-changelog.md). A tool's scope is not really settled until its ADR (where one exists) agrees with this document.

**Status vocabulary — exact, not blurred:**

| Word | Means |
|---|---|
| **Shipped** | Built, passing its gate in the corpus. |
| **Foundation built** | The machinery exists; no scanner uses it yet. |
| **Not built** | Planned only. |
| **Cut** | Deliberately not to be built. ADR cited. |
| **Blocked** | Cannot proceed. What blocks it is stated. |

---

## The scan modes

Every scanner exposes three modes: **Light**, **Standard**, **Deep/Validated**.

| | Light | Standard | Deep / Validated |
|---|---|---|---|
| What | Passive checks | Active checks | Standard + a proof pass on each finding |
| Cost | Free | Paid | Business tier |
| Permission | *Not a property of the mode* — see below. An active check needs verified ownership in **any** mode; a passive one needs none in any mode. | | |

**This changed in Phase 0b.6, and it is the part most likely to be misread from older docs.** Passivity is **declared per check**, not inferred from the mode name. A `Check` in a scanner's catalogue carries a `passive: bool` property (`core/authz.py`). `core/authz.py` enforces:

- An **active** check requires a valid, unexpired `authz_ref` (verified ownership) in **any** mode, Light included. Mode does not exempt an active check.
- A **passive** check needs no authorisation in any mode.
- **A check with no declaration counts as active.** `passive=None` is a legacy path kept only for the reference scanner; a real scanner's checks must all declare.

In practice, for the four shipped scanners (`email`, `tls`, `domscout`, `web`) every check happens to be passive, so **Light remains free and unauthorised in practice** — but that is a fact about their check catalogues today, not a rule the mode enforces. The next scanner to add an active Light-mode check (plausible for AI/agent exposure, see A1) will be denied by `core/authz.py` exactly as a Standard check would be, and that is correct behaviour, not a bug.

**Resolved 2026-09-01.** [docs/00-context.md](docs/00-context.md)'s scan-mode table carried the pre-0b.6 framing — permission as a property of the mode — and has been corrected to state the mechanism above, with the table row kept as a description of what is true of the two shipped scanners today rather than as the rule. The same correction was applied to [docs/12-cli-runbook.md](docs/12-cli-runbook.md), [docs/13-test-targets.md](docs/13-test-targets.md) and [docs/how-to-add-a-scanner.md](docs/how-to-add-a-scanner.md).

Full mechanism: `core/authz.py`. Legal grounding: [docs/09-ownership-verification.md](docs/09-ownership-verification.md).

---

## How every finding is shaped

Full schema: `contracts/finding.schema.json`. This section is the summary, not a restatement of the contract.

### Three separate axes

- **`severity`** — `critical` / `high` / `medium` / `low` / `info`. How bad, if true (or, for a dated finding, how bad *when* it lands — see below).
- **`confidence`** — 0–1. How sure we are. `confidence_provisional: true` on every finding until Phase 4 calibration; values before then are hand-assigned priors, not fitted.
- **`state`** — computed by `core/state.py`, **never hand-set** by a scanner. A scanner that hand-sets `state` is a bug.

Triage sorts by **`severity_weight × confidence`**.

### The five states

`confirmed` · `highly_likely` · `suspected` · `informational` · **`inconclusive`**

`confirmed` requires validation to have run and passed via an independent method. Returning `inconclusive` is correct and expected behaviour, not a failure to detect — timeout, WAF block, rate limit, ambiguous response, missing prerequisite all resolve here. Never guess, never silently drop.

### Control-vs-test evidence

**Every finding needs a control-vs-test pair.** "The server errored" is not evidence. "The server returned 47 rows for `1=1` and 0 for `1=2`, identical otherwise" is. No exceptions to this — see [docs/06-guidelines.md](docs/06-guidelines.md).

### The ADR-018 additions — dated and derived findings

Two orthogonal fields, added at two scanners deliberately (before ten made it a migration):

- **`materialises_at`** (+ `materialises_reason`) — `null` means true now, as every finding was before this addition; a date means the finding becomes true from that date. This is what the deprecation clock runs on: `severity` becomes "how bad when it lands," and the date, not the severity, is what makes it a claim about the future rather than the present.
- **`derivation`** — `detected` (an observation of the target, confidence from the confidence engine) or `derived` (a calculation from an observation plus a rule, confidence **inherited from the finding it derives from**, via `derived_from`). Confidence is never recalculated for a derived finding — arithmetic is not evidence, and forcing it through the confidence engine would mean inventing a fake likelihood ratio.

**A derived finding is never more confident than its weakest premise.** A correlation that chains three findings is only as believable as the least certain link ([ADR-022](docs/02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target)). Detected and derived claims are counted **separately** in every published gate number — see [docs/10-measurement.md](docs/10-measurement.md).

---

## The tool catalogue, A1–A19

Content source: [docs/reference/product-spec.md](docs/reference/product-spec.md) (v2, corrected below where wrong). Gates and phase placement: [docs/03-roadmap.md](docs/03-roadmap.md). Corrections from v2 are called out inline as **[v2 said X → now Y]**.

### A1. Website Scanner — Tool 4a (`web`, Light) **Shipped**; 4b (AI/agent exposure) next

One-line: crawl and probe a site for header/cookie/config weaknesses (Light), injection and business-logic bugs (Standard), and — new in v3.4 — AI/agent exposure.

- **Light** — headers, cookies, directory listing, info disclosure, tech fingerprint, outdated components by version, robots/sitemap review, TLS summary. **[v2 said]** technology fingerprint DB would be "Wappalyzer-style" and implicitly comparable in accuracy → **[now]** unmeasurable and unearned as a claim; the DB is built independently and no accuracy comparison to Wappalyzer is made. **[v2 said]** the DB is ours to build freely → **[now]** Wappalyzer's fingerprint database and its forks are GPL-3.0 and must not seed ours (CLAUDE.md hard constraint 4).
- **Standard** — full JS-rendered crawl, hidden file/dir discovery, historical URL mining, reflected XSS, SQLi, SSRF (via OOB), path traversal/LFI, open redirect, CORS misconfig, auth/session weaknesses, CVE matching. **Descoped from v2**: DOM XSS and stored XSS moved to Phase 2.5 ([docs/03-roadmap.md](docs/03-roadmap.md) Phase 2).
- **Deep** — validation engine confirms each Standard finding via an independent method; blind classes proven via OOB callback.
- **New in v3.4**: AI and agent exposure — MCP servers, agent admin panels, unauthenticated model endpoints, **passive detection only**. Finding a server is passive; reading its admin panel is not, and the AI-exposure checks must each carry their own `passive` declaration under 0b.6 rather than inherit one from the mode.
- Mechanism: crawler (ZAP's, Apache-2.0, to start — **[v2 said]** Nuclei for template checks; ZAP crawler as a stopgap → still the plan, unchanged), own injection engine, own content-discovery engine, web-archive APIs, OOB callback client.
- **Status: Light shipped — Tool 4a (`web`) v1.0.5, live-verified on v1.0.1** (v1.0.5, 2026-10-09: evidence carries redaction receipts, ADR-029; v1.0.4, 2026-10-09: the scanner-side redaction workaround is removed, because core redacts every storage point, ADR-028) (ADR-017/ADR-024; build log and live-verification results in the [ledger](docs/14-progress-ledger.md#2026-10-07--tool-4a--website-scanner-light-web-v101)). 21 checks, all passive: transport and redirect, security headers, CSP, page content, error pages and directories. **Tool 4a is the passive half only. Tool 4b (AI/agent exposure) is the next tool and is not built;** its spec starts with the passivity ADR. **Standard and Deep: not built** — blocked on the OOB callback server (Phase 2a, not built); HTTP record/replay is done (0b.4).
- **Deferred from Light:** cookie-flag checks and cookie-name fingerprints (ledger D-W1) — they need a core redaction change first (D21), so they are owed, not dropped.
- **Gate, Light (Tool 4a):** precision ≥ 0.95, recall ≥ 0.85 (corpus-relative), inconclusive ≤ 0.15 ([roadmap](docs/03-roadmap.md), Phase 1 Tool 4). **Actual, from `make corpus` (2026-10-08, v1.0.3, unchanged from v1.0.1):** `precision 1.000, recall 1.000, susp% 3.4%, inconc% 0.9%, PASS` — 234 checks run, **10 claims** (`confirmed`/`highly_likely`) over an 11-case lab corpus. Read the claim count with the number: 1.000 rests on ten claims, not 234 checks, and those ten come from the header-policy and directory-listing families only — debug-mode, secret-in-response, error-disclosure, EOL, SRI and mixed content land at `suspected`, are excused from the gate, and so are not covered by the 1.000; and the recall is **corpus-relative** (a corpus we wrote ourselves; "all header misconfigurations on a site we don't fully understand" is not a knowable set), never an absolute figure. Hand-verified live against 13 hosts with zero false positives — see the ledger. **Correction:** this entry previously said "No Light-mode gate is set in the roadmap"; it is — the roadmap's Phase 1 table has carried it since v3. Fixed here, not by adding a document (CLAUDE.md rule 4).
- **Gate, Standard/Deep (not built):** precision ≥ 0.90 overall (`confirmed` ≥ 0.98), recall ≥ 0.75 on the benchmark tier, inconclusive ≤ 0.15, ≥ 0.95 of blind-class findings proven via OOB. Recall is **benchmark-true, corpus-relative elsewhere** — never publish it as absolute for Light.
- Depends on: A4 (asset discovery), Phase 2a (OOB server), asset graph (0b.2, done).
- Constraint: no Nuclei-as-embedded-scanner claim beyond template use; **[v2 said]** "import Burp findings" as an offset for not embedding Burp — still the plan (ADR-010).

### A2. Network Scanner

One-line: port discovery plus scoped service fingerprinting.

- **Light** — host discovery, top-100-port scan, service name ID, per-port risk rating.
- **Standard** — full 65,535-port scan, service version detection, CVE matching.
- Mechanism: naabu (MIT) for discovery. **[v2 said]** Nmap as "the best-known tool" with a licence workaround via OEM purchase → **[now, ADR-003]** Nmap is flatly forbidden, including inside a container, no OEM path considered. **naabu is port discovery only** — no service/version detection; our fingerprinting is scoped to ~50 services with **no claim of Nmap parity**.
- **Status: Not built.**
- Gate: not yet set in the roadmap for this tool specifically; inherits the standard three-number discipline ([docs/10-measurement.md](docs/10-measurement.md)).
- Depends on: rate limiting / adaptive backoff (built, `core/ratelimit.py`).

### A3. SSL/TLS Analyzer — Tool 2, **Shipped**

One-line: certificate, chain, protocol and cipher analysis, plus (v1.1) certificate-lifetime readiness and post-quantum exposure.

- **Light** — cert validity, expiry, issuer, domain match, chain completeness, self-signed/untrusted warning.
- **Standard** — supported protocol versions, cipher list, PFS, HSTS (D10, unblocked by 0b.4, not yet written), CT log presence, named-vulnerability inference by version/config (never active exploitation — **[v2 said]** testssl.sh's named-vulnerability probes would be reused → **[ADR-016, now]** we do not reuse them at all: most send deliberately malformed input, which ADR-004 already forbids, so testssl.sh's deepest asset never transfers).
- **[v2 said]** an A+–F grade "like SSL Labs" → **deferred by decision (D9)**: a grade is an opinion and gets argued with; facts don't. Not built, may ship later with the full rubric visible if it does.
- Mechanism: **our own TLS engine** in Python's `ssl`/ stdlib, not a testssl.sh wrapper. **[v2 said]** "build our own in Go... recommended long term" or wrap testssl.sh → **[ADR-016, now]** own engine decided and built; testssl.sh runs only as an external cross-check (`make crosscheck`), GPLv2, subprocess only, never linked.
- **v1.1 additions (v3.4):** certificate lifetime readiness (dated, `materialises_at` set to the date renewal cadence breaks) and post-quantum exposure. Post-quantum is **Blocked on Python 3.15** (`ssl.SSLContext.set_groups`/`get_groups`, `SSLSocket.group()`) — **not 3.13 as the roadmap originally and incorrectly stated (D16, corrected 2026-08-28).** Certificate lifetime readiness has no such blocker and is Not built yet.
- **Status: Shipped, v1.2.0.** 19 checks — 8 Light, 11 Standard, **all passive** ([ADR-023](docs/02-decisions.md#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active)) — so TLS needs no authorisation in any mode, like email. Includes `tls-vuln-beast`, the first **derived** finding any scanner emits ([ADR-018](docs/02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived); confidence inherited from `tls-protocol-obsolete`). RC4/Sweet32/Logjam are **unblocked (D20)**: `tls-vuln-rc4`, `tls-vuln-sweet32`, `tls-vuln-logjam` wrap testssl.sh at runtime, Standard mode only, per ADR-016's amendment, with real corpus positives recorded against public badssl.com weak endpoints. `tls-vuln-freak` ships (same mechanism) but has **no corpus positive** — `export.badssl.com` no longer negotiates an export-grade suite against either engine, so no live public endpoint remains to record one from; deferred, not faked. Gate met, 220 checks, 1.000/1.000.
- **Gate:** precision ≥ 0.98, recall ≥ 0.95, inconclusive ≤ 0.15. **Actual, from `make corpus` (2026-09-02, v1.2.0):** `precision 1.000, recall 1.000, PASS` — 220 checks run, **5 claims** (`confirmed`/`highly_likely`). Read the claim count with the number: most findings land as `suspected` (honest — one `independence_class` — and excused from the gate on both sides), so 1.000 rests on five claims, not 220.
- **Declared limit: no `tls` check can reach `confirmed`** (2026-10-08, from [the scanner catalogue](docs/21-scanner-catalogue.md#tls--ssltls-analyzer-tool-2-v120)). `tls` has no validation step: nothing re-observes a finding after it is made, and `core/state.py` requires a passed validation for `confirmed`. Its ceiling is `highly_likely`, reached when two readings of the same handshake agree: our certificate parse and OpenSSL's trust-path verdict. **All 5 claims behind the gate number are `highly_likely`; none is `confirmed`.** They are not the same kind of evidence as `web`'s 10 claims (9 `confirmed` by re-observation on a second page, 1 `highly_likely`). Anyone quoting `tls`'s 1.000 must say it rests on 5 unvalidated claims.
- **Caveats that belong here, not buried:** 14-case corpus, cross-checked against testssl.sh. Six real defects across Tools 1 and 2 survived their corpora at precision 1.000 — three of the six were in the TLS lab itself (a CA missing `basicConstraints`, servers accepting TLS 1.0, a two-level chain standing in for an incomplete one), found only by reading the fixtures, not by the harness. Certificate revocation checking (OCSP/CRL) is not built — `revoked.badssl.com` currently returns nothing, which reads as a pass (D12). No weak-cipher (`RC4`/`3DES`) positive case exists; OpenSSL 3 compiles them out (D11).
- Depends on: HTTP record/replay for HSTS (done, 0b.4).

### A4. Domain & Subdomain Enumeration — Tool 3 (`domscout`), **Shipped (Light) v1.1.0 — live-verified on v1.0.0**

> **2026-10-08: two advertised checks are broken in production while the gate passes.** `domain-expiring` has never read an expiry date live ([ledger D28](docs/14-progress-ledger.md#d-deferred-register)). The S3 and Heroku takeover fingerprints can never fire (D31). Both come from fixtures that fabricated a third party's behaviour ([ADR-027](docs/02-decisions.md#adr-027--a-fixture-may-stand-in-for-a-real-service-only-on-recorded-evidence)). Do not quote domscout's gate number.

One-line: the asset list every other tool scans, plus subdomain-takeover detection.

- **Light** — subdomains from CT logs (crt.sh), all DNS record types, RDAP domain-expiry, nameservers, DNSSEC delegation state, and **dangling-CNAME subdomain-takeover** (passive under [ADR-023](docs/02-decisions.md#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active): ordinary DNS plus at most one ordinary HTTPS GET, never claiming the resource). **[v2/earlier SPEC said]** takeover was a Standard item → **[now]** the dangling-CNAME check is passive and ships in Light, matching the roadmap row; active brute-forced takeover stays Standard.
- **Standard (not built)** — active brute-force, liveness check, tech-per-subdomain, AXFR misconfig check, deeper-label wildcard detection, related-domain discovery, OSINT harvesting, shadow IT discovery.
- Mechanism: own crt.sh + DNS + RDAP + takeover-fingerprint code (no third-party enumerator embedded); subfinder/dnsx/httpx/Amass are the **cross-check** references (ADR-024), not embedded.
- **The recall model (settled, and it changed the spec):** subdomain enumeration is **informational inventory, not a vulnerability**, so it is **not** confidence-scored and **not** gated on precision/recall — `core/state.py` maps `info` severity to `informational`, which [docs/10-measurement.md](docs/10-measurement.md) excludes entirely. The gate applies **only to the real security findings** (`dnssec-status`, `domain-expiring`/`domain-expired`, `subdomain-takeover`). Enumeration is guarded against *false discovery* by the no-false-discovery corpus cases, and its *completeness* is assessed **live** against subfinder/crt.sh as a disagreement comparison — never published as a score. This supersedes the "two-number recall" framing in the design spec's §1; the ledger records why.
- **Status: Shipped (Light), v1.1.0** (2026-10-09, v1.1.0: `secret-exposed`, a credential in a target response the scan fetched is reported and never stored, ADR-029, UNDETERMINED until a real positive), gate met and **live-verified against `codez.in`** (ADR-017/ADR-024): the `dnssec-status` claim hand-verified with `dig`, discovery cross-checked against `subfinder`. Two items remain owed (ledger D-DS1/D-DS2): the `kinetrix` domains' live runs, and the single-source coverage gap below.
- **Known coverage limit (D-DS1), stated plainly:** enumeration seeds from **crt.sh only**. A subdomain with no certificate in the CT logs is not discovered, so recall is materially below a multi-source tool (`subfinder` found ~68 names to our 16 on `codez.in` — though most of its extras do not resolve). Everything we report is real; what we miss is names outside CT logs. The path to close it is adding more passive sources (certspotter's CT API, then passive DNS) under the same passivity/replay rules — not built yet. **No Nmap-parity-style completeness claim is made.**
- **Gate:** precision ≥ 0.95, recall ≥ 0.80, inconclusive ≤ 0.15. **Actual, from `make corpus` (2026-09-03):** `precision 1.000, recall 1.000, PASS` — 50 checks, **1 claim** (`dnssec-status`, `confirmed` via independent second-resolver validation). Read the number with its claim count: expiry and takeover are honest `suspected` (excused), and enumeration is informational (excluded), so the gate rests on one validated claim — thinner than TLS's five, stated plainly.
- Depends on: asset graph (0b.2, done) — this is the tool the graph mechanism exists for; it discovers assets onto the shared graph rather than reading one seeded for it. First real producer for the graph.

### A5. Deface / Change Monitoring

One-line: baseline + diff, alert on unexpected content change.

- **Light** — homepage baseline (HTML hash + screenshot), simple change detection, title/meta alerts.
- **Standard** — multi-page monitoring, visual diff, injected-content detection (hidden links, iframes, miners, redirects), malware/blacklist check, new third-party script detection, alert routing, configurable frequency.
- Mechanism: Playwright/Chromium, a diff library, Safe Browsing / VirusTotal APIs, a scheduler.
- **Status: Not built.**
- Gate: not yet defined — this is a monitoring feature, not a one-shot scan; measurement discipline for it is an open item.
- Depends on: A1's crawler.

### A6. API Scanner

One-line: BOLA/BFLA and injection testing on REST/GraphQL/SOAP, held to two-identity session testing rather than a web scanner pointed at a URL.

- **Light** — endpoint discovery, OpenAPI/Swagger parsing, GraphQL introspection check, missing-auth detection, security headers, HTTP method testing, rate-limit presence.
- **Standard** — BOLA/BFLA (needs a session manager holding **two identities at once**), injection testing, mass assignment, excessive data exposure, JWT weaknesses, API key exposure, GraphQL depth abuse, spec drift, OWASP API Top 10 mapping.
- **[v2 said]** "almost nobody does BOLA testing" as the differentiating claim → **[ADR-014, now]** false since Dec 2025 — StackHawk shipped multi-identity business-logic testing, Escape and Akto already had it. **Build the feature; never make the novelty claim.**
- **Status: Not built.**
- Gate: not yet set.
- Depends on: A1's crawler/session infrastructure.

### A7. Email Security Scanner — Tool 1, **Shipped**

One-line: SPF/DKIM/DMARC configuration and spoofing risk.

- **Light** — SPF present/valid, DKIM detection, DMARC policy, MX listing, spoofing-risk verdict.
- **Standard** — SPF syntax + DNS-lookup-count analysis, SPF too-permissive check, DKIM key strength, DMARC alignment mode, DMARC reporting addresses, BIMI, MTA-STS/TLS-RPT, open-relay test, mail-server TLS, blacklist status, look-alike domain detection.
- **Not built from v2 scope:** open-relay test and mail-TLS check (D4 — need SMTP connections, active not passive, deferred without blocking the gate) and look-alike domain detection (D5 — needs RDAP + a permutation engine, larger than the rest of Tool 1 combined).
- **Status: Shipped, v1.5.0** (2026-10-09, v1.5.0: `secret-exposed`, a credential in a public DNS record the scan read is reported and never stored, ADR-029, UNDETERMINED until a real positive; v1.4.1: an independent review of the RFC 9989 work found and fixed 11 blockers over four passes; DMARC read under RFC 9989 with RFC 7489's differences stated, and three new checks; DMARC discovery by RFC 9989's tree walk, so a subdomain no longer gets a false `dmarc-missing`; 2026-10-08: D47, no transport advice for domains that accept no mail; D45, the DMARC version is case-sensitive; 2026-10-08: claim defects fixed before the live re-verification, and second-resolver validation made real by D39; see the ledger). 20 checks, gate met.
- **Live-verified 2026-10-08 (email live run 2, [verification](corpus/crosscheck/email-live/2026-10-08-run2/verification.md)): 45 domains, all 146 non-informational findings hand-verified, checkdmarc as cross-check.** Of 144 claims, **139 are true and 5 false (live precision 0.965)**. All 5 false claims are DMARC claims, judged against **RFC 9989, which obsoletes RFC 7489** ([ledger D44](docs/14-progress-ledger.md#d-deferred-register)). Every SPF, DKIM, MX, MTA-STS and TLS-RPT claim (117) is true. **Quote the live result, not the corpus gate.** D44 is fixed in v1.4.0: DMARC is read under RFC 9989 first, with RFC 7489 stated where it differs (ADR-017). D45 is fixed in v1.2.1.
- **Until 2026-10-08, production `confirmed` was never validated by a second resolver ([ledger D39](docs/14-progress-ledger.md#d-deferred-register)): the re-query labelled 8.8.8.8 was sent to 1.1.1.1. Fixed that day.** Evidence produced before the fix that names a second resolver is misattributed and is not two-resolver confirmation. The live disagreement rate is measured in [the ledger](docs/14-progress-ledger.md).
- **Gate:** precision ≥ 0.99, recall ≥ 0.95, inconclusive ≤ 0.15. **Actual, from `make corpus` (2026-09-01):** `precision 1.000, recall 1.000, susp% 0.0%, inconc% 0.8%, PASS` — 240 checks run, **21 claims**. **v1.1.0 (2026-10-08): 240 checks, 20 claims**, since `dmarc-malformed` is now `suspected`.
- **Caveats:** 16-case corpus of **synthetic zones we wrote ourselves** — proves the checks do what was intended, not that intent matches the world (D6: ~50 real domains as a frozen tier is owed, not built). Six real defects across Tools 1 and 2 survived corpora at precision 1.000; live verification against real domains is part of a tool's definition of done (ADR-017), not optional polish.
- Depends on: nothing further; passes without D4/D5.

### A8. Container Scanner

One-line: Docker image and Kubernetes config scanning, with mandatory reachability filtering against noise.

- **Light** — image metadata, base-image age, OS-package CVEs, exposed ports, root-user check, Dockerfile best practices.
- **Standard** — full CVE scan (OS + app deps), embedded secrets, CIS Docker Benchmark, Kubernetes manifest/RBAC analysis, image signature/provenance, layer breakdown, SBOM.
- Mechanism: Trivy, Syft, Grype, Checkov/KICS — all Apache-2.0.
- **Status: Not built.**
- Gate: not yet set.
- Constraint: **reachability filtering is mandatory**, not optional — a base image yields 500+ CVEs unfiltered, mostly unexploitable; without filtering this tool is noise users ignore. (Distinct from A9's reachability, which is cut — see below.)

### A9. Supply Chain Scanner

One-line: dependency CVE matching, direct-dependency only.

- **Light** — dependency list from manifests, direct-dependency CVEs, outdated-package detection, licence listing.
- **Standard** — transitive tree, typosquatting/dependency-confusion detection, abandoned-package detection, suspicious install-time behaviour, package integrity/signature verification, CI/CD config security, third-party script analysis, licence compliance, SBOM export.
- **[v2 said]** reachability analysis ("is the vulnerable function actually called") as "the differentiator," full Standard-scope item → **[CUT, ADR-014]**. This is Endor Labs' entire product; a single-language MVP is a 3–6 month job that would still be visibly worse. **Direct-dependency matching via OSV.dev only, using direct-vs-transitive as a crude noise proxy, and we say plainly that we do not do reachability.**
- **Status: Not built.**
- Gate: not yet set.

### A10. Cloud Security Posture Management (CSPM)

One-line: read-only cloud config assessment, narrowed to linking outside-in findings rather than competing on breadth.

- **Light** — read-only role connection, resource inventory, public buckets/DBs, open security groups, unencrypted volumes, root MFA status.
- **Standard** — full CIS Benchmark per cloud, IAM over-privilege analysis, privilege-escalation path detection, logging/monitoring gaps, encryption gaps, network architecture review, compliance mapping, multi-account view, **link to external scan results**.
- **[v2 said]** "our angle" is loosely defined breadth-plus-linking → **[03-roadmap Phase 5, now]** explicit: **do not compete with Wiz on breadth**; the angle is narrow — "this exposed subdomain points to this instance, which has this role, which can read this bucket."
- Mechanism: Prowler (Apache-2.0) primary; ScoutSuite (GPL) as an alternative, **subprocess isolation only, never linked** (CLAUDE.md hard constraint 4).
- **Status: Not built.**
- Gate: not yet set.
- Constraint: **chokepoint/attack-path analysis using this data is CUT** — see "What is cut" below.

### A11. Code Scanner (SAST + Secrets)

One-line: static analysis plus secret detection with live validation, scoped to a maintained provider list rather than TruffleHog-style breadth.

- **Light** — repo connection, language detection, hardcoded-secret detection, basic insecure patterns, dependency manifest scan.
- **Standard** — full static analysis with data-flow tracking, injection detection in code, auth/authz logic flaws, insecure crypto usage, secrets across git history, **live secret validation** (top 15–20 providers, framed as permanently ongoing, per-provider ToS review required before validating), IaC scanning, PR integration, CI/CD integration.
- **[v2 said]** Semgrep (with the note that its rules changed licence Dec 2024) → **[ADR-003, now, confirmed]** Semgrep's own rules are unusable in a competing SaaS. **Opengrep + our own rule corpus**, never Semgrep's rules.
- **[v2 said]** TruffleHog for secret validation, "legal check needed" → **[ADR-003, now, resolved]** TruffleHog is AGPL-3.0 and is **not used** — Gitleaks (MIT) for detection plus our own validator, scoped to ~15–20 providers rather than TruffleHog's 800+, because that breadth is an integration programme, not a feature.
- **[v2 said]** MobSF listed generically under A13 as "open source" → see A13 correction; the licence issue is MobSF's, not Opengrep's, but both v2 entries needed the same fix: check the actual licence, don't assume "open source" means embeddable.
- **Status: Not built.**
- Gate: not yet set.

### A12. AI/LLM Application Scanner

One-line: adversarial prompt testing reported as a probabilistic success rate, not a yes/no.

- **Light** — LLM-in-use detection + provider ID, exposed AI API keys in frontend code, rate-limit presence, system-prompt visibility client-side.
- **Standard** — prompt injection (direct/indirect), system-prompt leakage, sensitive-data extraction, excessive agency, insecure output handling, unbounded consumption, RAG cross-user leakage, vector DB/embedding weaknesses, OWASP LLM Top 10 mapping.
- Mechanism: garak (Apache-2.0), PyRIT (MIT), own prompt corpus.
- **Status: Not built.**
- Gate: not yet set — probabilistic reporting (success rate over N attempts) needs its own measurement treatment, not binary precision/recall.
- Note: distinct from A1's *passive* AI/agent-exposure checks (finding an MCP server); this tool actively probes an LLM application's behaviour.

### A13. Mobile App Scanner

One-line: static analysis of APK/IPA plus testing of the backend APIs the app talks to.

- **Light** — app metadata/permissions, exported components, debuggable flag, hardcoded strings.
- **Standard** — hardcoded secrets/keys, insecure local storage, weak crypto, cert pinning check, insecure network config, third-party SDK inventory, **backend API testing** (the valuable half).
- **[v2 said]** MobSF described simply as "open source" → **[CLAUDE.md hard constraint 4, corrected]** MobSF is **GPLv3**, and being a Django app rather than a CLI binary, it **must run as its own containerised service talked to over HTTP, never imported** — the same rule as ScoutSuite and testssl.sh, stated explicitly because "open source" in v2 elided the licence class that actually matters here.
- **Status: Not built.**
- Gate: not yet set.
- Depends on: A6's API testing engine for the backend half.

### A14. Dark Web / Credential Exposure Monitor

One-line: breached-credential alerts for verified domains, licensed source only.

- Breach hits for verified domains, breach/date/data-type, new-exposure alerts, password-reuse risk.
- Mechanism: a licensed provider (e.g. HIBP commercial API) only. **Never scrape criminal marketplaces or buy stolen data** (CLAUDE.md/ADR).
- **Status: Not built.** Legal review is a prerequisite, not a follow-up.
- Gate: not applicable in the precision/recall sense — this is licensed-source pass-through, not detection.

### A15. Third-Party / Vendor Risk Scanner

One-line: Light Scan pointed at a user's suppliers, passive only.

- Security rating per vendor, public-facing issues, cross-vendor comparison, exportable report.
- **Passive only** — the user does not own these domains; this is a legal boundary, not a preference.
- **Status: Not built.** Near-zero new engineering once A1/A3/A4/A7 exist — reuses their Light modes.
- Gate: inherits whichever scanner's Light-mode gate is reused.

### A16. Compliance Readiness Scanner

One-line: maps findings to a chosen framework and shows the gap.

- Framework selection (SOC 2, ISO 27001:2022, PCI DSS 4.0.1, GDPR Art.32, HIPAA, NIST CSF 2.0), control-by-control status, gap list, evidence pack.
- **Must say "compliance readiness," never "compliant"** (ADR-011, CLAUDE.md hard constraint 6) — legal distinction, not phrasing preference.
- **Status: Not built.**
- Gate: not applicable in the accuracy-gate sense — correctness here means correct mapping, not detection precision/recall.

### A17. Attack Surface Monitor

One-line: continuous diff over discovered assets — new subdomain, new port, cert expiring, tech-version change, new CVE affecting the stack, score change.

- **Status: Not built.** Commercially named as the single most important item for converting one-time scans to subscriptions — a framing note, not a build note.
- Gate: not yet set; this is a diff over other tools' outputs, so its correctness is bounded by theirs.
- Depends on: A1/A3/A4 outputs and the asset graph (done, 0b.2).

### A18. Security Score & Reporting

One-line: 0–100 score plus per-area sub-scores, always clickable to the findings that caused it.

- **Rule, not a preference:** every score must be clickable down to the exact findings that caused it. An unexplainable score destroys trust with technical users ([docs/06-guidelines.md](docs/06-guidelines.md)).
- **Status: Not built.**
- Gate: not applicable in isolation — correctness is inherited from the findings underneath.

### A19. IoT & Device Security Scanner *(new in v3.4, ADR-021)*

One-line: takes a network (not a domain), inventories devices, and reports exposure/vulnerability without touching a credential, writing, or changing state. Split into two tools deliberately — full detail in [docs/15-iot-scanner.md](docs/15-iot-scanner.md), summarised here.

**5a — Device Exposure**
- Discovery: mostly listening (mDNS/DNS-SD, SSDP/UPnP, DHCP fingerprints/MAC OUI) plus direct probes of ~12 known device ports on an authorised range — **not** port discovery in the naabu sense.
- Identification via UPnP device-description XML / mDNS TXT records → `vendor · model · firmware`; an undetermined identification is itself a finding, not silence.
- Encryption checks (`iot-telnet-enabled`, `iot-mqtt-plaintext`, `iot-coap-no-dtls`, `iot-admin-http-only`, `iot-snmp-v1-v2c`) — `confirmed`, no inference, the recommended first-release set.
- Authentication checks via protocol-native control-vs-test pairs (MQTT `CONNACK`, CoAP `.well-known/core`, admin-panel status codes) — **connecting is a handshake, reading is not**: never subscribes, never reads a resource, never enumerates.
- **Default credentials are detected from model, never tried** — `iot-default-credential-documented` stays `suspected` permanently.
- **Status: Not built.** Dependencies (protocol clients in `core/`, generic record/replay) are Phase 0b items only — 5a could be pulled forward ahead of the Network Scanner, an open, not-yet-decided placement question.
- **Gate:** precision ≥ 0.95, recall corpus-relative.

**5b — Device Vulnerability**
- CVE matching from `vendor · model · firmware`, honestly noisy by nature: firmware-version-unparseable → `inconclusive` (not "no vulnerabilities"); fuzzy vendor+model match → `suspected`, described as fuzzy; exact CPE + version in range → `suspected`, confidence ≤ 0.6; version match + behavioural confirmation → `highly_likely`.
- **A documented exception to the version-strings-lie rule**: IoT vendors rarely backport (new build or nothing), so `firmware_version` may justifiably carry a higher confidence cap than a distro package version — **the corpus must demonstrate this before the cap moves**; it is not yet moved.
- `iot-firmware-end-of-support` is a **derived, dated finding** — the deprecation clock applied to devices.
- **Status: Not built.** Depends on 5a, plus a CVE source (OSV.dev approved but thin IoT coverage; NVD CPE matching may be needed, licence/rate-limit unresolved).
- **Gate:** precision ≥ 0.90, recall corpus-relative — deliberately lower than 5a because it infers from an identifier rather than observing.

**Safety — stop-the-line, not a default to tune away:** device-class rate ceilings are floors; one connection at a time per device; never repeat an unanswered probe; read-only verbs only (no MQTT PUBLISH/CoAP write verbs/SNMP SET/UPnP control actions); authorisation requires someone who understands the physical consequence of a device falling over. Full rules: [docs/06-guidelines.md](docs/06-guidelines.md).

**Corpus caveat, stated plainly per ADR-017:** real devices violate their own specs constantly, and an emulator written from the same RFC as the scanner will agree with it — this is the corpus-encodes-the-author's-assumptions failure in its purest form. A real device network to verify against (D15) is a prerequisite for calling either half done, not a nice-to-have.

---

## Platform features, B1–B12

All **Not built** — Phase 6, per [docs/03-roadmap.md](docs/03-roadmap.md); nothing has a UI before then (ADR-001, ADR-012). Content source: [docs/reference/product-spec.md](docs/reference/product-spec.md) B1–B12, unchanged from v2 except where noted.

| # | Feature | One-line | Correction from v2 |
|---|---|---|---|
| **B1** | Account & onboarding | Signup (email/Google/GitHub); Light Scan with no signup; ownership verification (DNS TXT/file/meta tag/email); bulk/CSV/auto-discover assets; criticality/environment tags; project grouping. | None. |
| **B2** | Scan management | On-demand/scheduled scans; live progress; pause/stop; history; compare two scans; re-scan one finding — the last item is now the built `scan verify` operation (0b.8), not a UI-only idea. | Grounded: "re-scan a single finding" is ADR-022's *close*, already built at the CLI layer. |
| **B3** | Findings management | One prioritised cross-tool list; filter/group; false-positive w/ reason; accept-risk w/ expiry+approver; owner; comments; full status history; search. | None. |
| **B4** | Request Replay | Edit-and-resend any request our scanner made; response/timing view; save/name; compare; export curl. Only against verified-owned assets, same rate limits as a scan. | None. |
| **B5** | Canary Token Generator | URL/DNS/email/document/API-key tokens; alert on access. Reuses the OOB server built for Phase 2a. | None. |
| **B6** | Payload Library | Curated, versioned test payloads by vulnerability class; user-visible provenance per finding; Business-tier custom payloads. | None. |
| **B7** | AI assistant | Explain a finding per audience; answer questions grounded in our evidence only; "what to fix first"; "why did my score change." | Grounded by [docs/06-guidelines.md](docs/06-guidelines.md): "never invents findings, never speculates beyond the evidence, says 'the evidence does not show that.'" |
| **B8** | Reporting | Exec summary, full technical, developer-focused, compliance evidence pack, change report, white-label, scheduled delivery, CSV/JSON/SARIF export. | None. |
| **B9** | Alerts & integrations | Email/Slack/Teams/webhook/PagerDuty; ticketing (Jira/Linear/GitHub Issues/ServiceNow); repo connectors; CI/CD; cloud connectors; SIEM export; REST API; CLI; **import findings from other scanners** (Burp/Nessus/Qualys/ZAP/Snyk). | None — import-as-strategy still stands (ADR-010). |
| **B10** | Learning & guidance | Plain-language vuln-class explanations, attacker's-eye-view, secure-coding examples, OWASP/CWE links, guided first-run walkthrough. | None. |
| **B11** | Team & access control | Multi-user orgs; Owner/Admin/Engineer/Auditor/Viewer roles; per-project permissions; SSO (SAML/OIDC); audit log; retention settings; data residency. | Phase 7, not Phase 6 — v2 did not separate these. |
| **B12** | Billing & usage | Free/Pro/Business/Enterprise tiers; daily credits that refresh and do not accumulate; usage dashboard; 80% warning; **hard stop, never surprise billing**; invoice history. | None. |

---

## What is cut and must not be built

All three from [ADR-014](docs/02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own), reaffirmed by [ADR-020](docs/02-decisions.md#adr-020--amends-adr-014-what-we-claim-now-that-the-ground-has-moved): "nothing in the 2026 research changes any of that."

| Cut | Where it would have shown up | Why |
|---|---|---|
| **Attack-path / chokepoint analysis** | Would-be C4 platform feature; touches A10 CSPM | Wiz's and XM Cyber's core product; needs an IAM/resource graph that does not exist until Phase 5's CSPM ships, which makes a Phase 4 item secretly depend on Phase 5. Phase 4 ships **basic same-asset correlation** (ADR-022's *connect*) instead — hand-written composition rules over the asset graph, not a graph engine. |
| **Reachability analysis** | A9 Supply Chain Scanner's headline feature in v2 | Endor Labs' entire product. A single-language MVP is 3–6 months and would still be visibly worse. A9 does **direct-dependency matching only** and says plainly that it does not do reachability. (Distinct from A8 Container Scanner's reachability *filtering*, which stays mandatory — filtering noise out is not the same claim as reachability-as-a-differentiator.) |
| **"Almost nobody does BOLA testing"** | A6 API Scanner's novelty claim in v2 | False since Dec 2025 (StackHawk, Escape, Akto). **Build the feature. Never make the claim.** |

---

## Licence and tooling rules

Full text: [docs/02-decisions.md](docs/02-decisions.md) ADR-003, [docs/06-guidelines.md](docs/06-guidelines.md). Summary for this catalogue:

**The rule:** permissive OSS may be embedded; commercial, restrictive, or legally-unclear tools may not. We build the capability ourselves and import their output instead.

**Approved and used:** naabu, Trivy, Syft, Grype, Checkov/KICS, Prowler, subfinder, dnsx, httpx, Amass, Opengrep, Gitleaks, garak, PyRIT, ZAP's crawler (Apache-2.0), OSV.dev, NVD (with its own CPE caveats).

**Forbidden, no exceptions:**
- **Nmap** — licence bars inclusion even inside a container. Use naabu (port discovery only, no service/version detection — no Nmap-parity claim anywhere).
- **Nessus, Burp, Acunetix, Invicti** — commercial, cannot be embedded. Import their output (ADR-010).
- **Semgrep's rules** — changed licence Dec 2024, unusable in a competing SaaS. Use Opengrep + our own rule corpus.
- **TruffleHog** — AGPL-3.0. Use Gitleaks + our own validator, scoped to ~15–20 providers.
- **OpenVAS** — feed terms unclear for commercial service use.

**GPL, subprocess-only, never linked or copied:** testssl.sh (GPLv2, cross-check only — not the TLS engine), ScoutSuite (GPL), **MobSF (GPLv3, a Django app — runs as its own service, talked to over HTTP, never imported)**.

**Data-licence traps, not just code:**
- **Wappalyzer's fingerprint database and its forks are GPL-3.0** — must not seed our fingerprint DB, and no accuracy-comparison claim against Wappalyzer is made (it is unmeasurable and unearned).
- **Semgrep's rules** are a data-licence trap as much as a code one — the rules, not the engine, are what changed licence.

---

## Accuracy rules that bind every tool

Full text: [docs/06-guidelines.md](docs/06-guidelines.md), [docs/10-measurement.md](docs/10-measurement.md). These apply to every tool above, shipped or not — restated once here because every catalogue entry depends on them, not to duplicate the source docs.

- **Precision over recall.** A scanner that misses things is disappointing; one that cries wolf is worthless.
- **Version strings lie.** A finding derived from a version string alone caps at `suspected`, confidence ≤ 0.6, until a behavioural check or distro tracker confirms it — the largest false-positive category in the industry. (A19 5b documents a narrow, corpus-proven exception for firmware versions specifically — not a general loophole.)
- **`inconclusive` is the correct answer, not a failure.** Timeout, WAF block, rate limit, ambiguous response, missing prerequisite all resolve here. Never guess, never silently drop.
- **Every finding needs a control-vs-test pair.** "The server errored" is not evidence.
- **A new detection needs both a positive and a negative corpus case, a stated `independence_class`, and a hand-assigned prior with a written justification.** No exceptions.
- **Live verification is part of a tool's definition of done** (ADR-017), not optional polish. A corpus written by the scanner's author encodes the scanner's assumptions and proves regression, not correctness — **six real defects across Tools 1 and 2 survived their corpora at precision 1.000**, all found by live runs or fixture review, none by the harness.
- **A gate number is read with its claim count.** Precision counts only `confirmed`/`highly_likely`; 1.000 over 5 claims (TLS) and 1.000 over 240 checks with 21 claims (Email) are not the same evidence, even though both currently pass. Publish the claim count next to the number, always.
- **Detected and derived claims are counted, and published, separately** (ADR-018). A derived precision figure partly measures a rule we wrote, not the world.
- **`state` is computed by `core/state.py`, never hand-set.**
- **Gates are three numbers**, not two: precision, recall, inconclusive rate (≤ 15%), all defined exactly in [docs/10-measurement.md](docs/10-measurement.md) — excluding `inconclusive` from the ratio without capping it separately would let a scanner score perfectly by shrugging at everything.
- **Confidence is provisional until Phase 4 calibration**, and calibrates per `(scanner × detection_method)`, never per `check_id` — undersampled forever at current volume otherwise.
- **Recall is corpus-relative, not absolute, for DNS enumeration and Web Light** — "all subdomains" and "all header misconfigurations" are not knowable sets. Email and TLS have finite check surfaces, so their recall is true recall. Never publish a corpus-relative number as if it were absolute.

---

## Status summary table

Verified against the repo and `make corpus` (2026-10-07) — see the run at the end of this document.

**Live evidence for shipped checks — standing figure (updated 2026-10-09 for ADR-029, from [the scanner catalogue](docs/21-scanner-catalogue.md)).** The four shipped scanners run **68 checks: 40 WORKING, 3 BROKEN, 25 UNDETERMINED.** **37% of our shipped checks (25 of 68) have no evidence either way that they work in production, and 3 more (4%) are known broken, so 41% (28 of 68) have no evidence that they work.** (It was 39% (26 of 66) before ADR-029 added `secret-exposed` to `email` and `domscout`, both UNDETERMINED with no real positive yet. email v1.4.0 added three checks: one WORKING, two UNDETERMINED.) It was 63% (40 of 63) before email's live run. WORKING means the check fired correctly on a real, live target and was checked by hand. BROKEN means it is known not to work in production, **including any check that made a false claim on a live target, until that is fixed**. UNDETERMINED means no known defect, but no live evidence that meets the standard. The gate numbers below are corpus numbers and do not change this figure. Update it only by regenerating the catalogue.

| Tool / Feature | Status | Gate | Actual (where shipped) |
|---|---|---|---|
| A1 Website Scanner | **A1 Light (4a, `web` v1.0.5) shipped — live-verified; Standard not built; 4b (AI exposure) next** | **Light:** precision ≥0.95, recall ≥0.85 (corpus-relative), inconc ≤0.15. **Standard:** precision ≥0.90 (`confirmed`≥0.98), recall ≥0.75 (benchmark tier) | Light: 1.000 / 1.000 (recall corpus-relative), 234 checks, **10 claims**, 0.9% inconc, PASS |
| A2 Network Scanner | Not built | not yet set | — |
| A3 SSL/TLS Analyzer | **Shipped v1.2.0** | precision ≥0.98, recall ≥0.95, inconc ≤0.15 | 1.000 / 1.000, 220 checks, 5 claims (all `highly_likely`; no `tls` check can reach `confirmed`), PASS |
| A4 Domain & Subdomain Enum (`domscout`) | **Shipped (Light) v1.1.0 — live-verified on v1.0.0; kinetrix+coverage owed** | precision ≥0.95, recall ≥0.80, inconc ≤0.15 | 1.000 / 1.000, 58 checks, **1 claim**, PASS (v1.1.0) |
| A5 Deface Monitoring | Not built | not yet set | — |
| A6 API Scanner | Not built | not yet set | — |
| A7 Email Security | **Shipped** | precision ≥0.99, recall ≥0.95, inconc ≤0.15 | 1.000 / 1.000, 442 checks, 30 claims (v1.5.0; corrected 2026-10-09, the row still showed v1.4.0's 380/26 although main gave 400/29), 0.5% inconc, PASS. Live (run 2): 0.965 over 144 claims, before D44/D45 were fixed. **Not quotable: corpus-validated, live-unverified (D35)** |
| A8 Container Scanner | Not built | not yet set | — |
| A9 Supply Chain Scanner | Not built | not yet set | — |
| A10 Cloud CSPM | Not built | not yet set | — |
| A11 Code Scanner (SAST+secrets) | Not built | not yet set | — |
| A12 AI/LLM App Scanner | Not built | not yet set | — |
| A13 Mobile App Scanner | Not built | not yet set | — |
| A14 Dark Web / Credential Monitor | Not built | n/a (licensed pass-through) | — |
| A15 Third-Party / Vendor Risk | Not built | inherits reused scanner's gate | — |
| A16 Compliance Readiness | Not built | n/a (mapping correctness) | — |
| A17 Attack Surface Monitor | Not built | not yet set | — |
| A18 Security Score & Reporting | Not built | n/a (inherits) | — |
| A19a IoT Device Exposure | Not built | precision ≥0.95, recall corpus-relative | — |
| A19b IoT Device Vulnerability | Not built | precision ≥0.90, recall corpus-relative | — |
| B1–B12 Platform features | Not built (Phase 6/7) | n/a | — |
| Scanner Contract | **Foundation built** | n/a | frozen, `contracts/*.schema.json` |
| Asset graph | **Foundation built** | n/a | 0b.2 |
| HTTP/DNS/TLS record-replay | **Foundation built** | n/a | 0b.3/0b.4 |
| Finding store + `scan verify` | **Foundation built** | n/a | 0b.8 |
| Correlation pass | **Foundation built** | n/a | 0b.9 |
| Deprecation calendar | **Foundation built** | n/a | 0b.7 |
| Post-quantum exposure detection | **Blocked** | — | blocked on Python 3.15 final (D16) |
| Chokepoint/attack-path analysis | **Cut** | — | ADR-014 |
| Reachability analysis (A9) | **Cut** | — | ADR-014 |

`example` scanner (reference, not a product tool): 1.000 / 1.000, 3 checks, 2 claims, PASS — not counted in the product catalogue above.

**`make corpus` output used for this table (2026-10-07):**

```
scanner     checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
----------------------------------------------------------------------------
domscout        50    1    0    0      1.000    1.000   4.0%    0.0%  PASS
           recall is over the security findings; enumeration is informational, ungated
email          240   21    0    0      1.000    1.000   0.0%    0.8%  PASS
example          3    2    0    0      1.000    1.000   0.0%    0.0%  PASS
tls            220    5    0    0      1.000    1.000   7.7%   12.3%  PASS
web            234   10    0    0      1.000    1.000   3.4%    0.9%  PASS
           recall is corpus-relative only - never publish this as absolute
```

Numbers are pasted from the live run; the per-scanner recall annotations for `domscout`, `email`, `example` and `tls` are kept from the previous block. The harness's "recall is absolute" line for domscout applies to its gated security findings; subdomain enumeration is ungated (see A4).
