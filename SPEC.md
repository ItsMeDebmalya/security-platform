# SPEC — Build Specification

*The canonical, current-truth statement of WHAT we build and WHAT each tool must do.*

---

## What this document is, and is not

**This is the authority on WHAT to build.** It replaces [docs/reference/product-spec.md](docs/reference/product-spec.md) in that role — that file is the v2 catalogue, preserved verbatim as history, and is now a content source, not the authority.

This document is **not**:

- the schedule — that is [docs/03-roadmap.md](docs/03-roadmap.md);
- the decision record — that is [docs/02-decisions.md](docs/02-decisions.md);
- the strategy front door — that is [tools-and-features-list.md](tools-and-features-list.md);
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
| Permission | — | — | — |

**This changed in Phase 0b.6, and it is the part most likely to be misread from older docs.** Passivity is **declared per check**, not inferred from the mode name. A `Check` in a scanner's catalogue carries a `passive: bool` property (`core/authz.py`). `core/authz.py` enforces:

- An **active** check requires a valid, unexpired `authz_ref` (verified ownership) in **any** mode, Light included. Mode does not exempt an active check.
- A **passive** check needs no authorisation in any mode.
- **A check with no declaration counts as active.** `passive=None` is a legacy path kept only for the reference scanner; a real scanner's checks must all declare.

In practice, for the two shipped scanners every check happens to be passive, so **Light remains free and unauthorised in practice** — but that is a fact about Email and TLS's check catalogues today, not a rule the mode enforces. The next scanner to add an active Light-mode check (plausible for AI/agent exposure, see A1) will be denied by `core/authz.py` exactly as a Standard check would be, and that is correct behaviour, not a bug.

**Note on document drift:** [docs/00-context.md](docs/00-context.md)'s scan-mode table still reads "Permission: None / Verified ownership required / Ownership + agreement" as if permission were a property of the mode. That is the pre-0b.6 framing. It is not wrong about the two shipped scanners' current behaviour, but it does not state the per-check mechanism above. Flagged here rather than silently fixed — 00-context.md is not this document's file to edit unprompted.

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

### A1. Website Scanner

One-line: crawl and probe a site for header/cookie/config weaknesses (Light), injection and business-logic bugs (Standard), and — new in v3.4 — AI/agent exposure.

- **Light** — headers, cookies, directory listing, info disclosure, tech fingerprint, outdated components by version, robots/sitemap review, TLS summary. **[v2 said]** technology fingerprint DB would be "Wappalyzer-style" and implicitly comparable in accuracy → **[now]** unmeasurable and unearned as a claim; the DB is built independently and no accuracy comparison to Wappalyzer is made. **[v2 said]** the DB is ours to build freely → **[now]** Wappalyzer's fingerprint database and its forks are GPL-3.0 and must not seed ours (CLAUDE.md hard constraint 4).
- **Standard** — full JS-rendered crawl, hidden file/dir discovery, historical URL mining, reflected XSS, SQLi, SSRF (via OOB), path traversal/LFI, open redirect, CORS misconfig, auth/session weaknesses, CVE matching. **Descoped from v2**: DOM XSS and stored XSS moved to Phase 2.5 ([docs/03-roadmap.md](docs/03-roadmap.md) Phase 2).
- **Deep** — validation engine confirms each Standard finding via an independent method; blind classes proven via OOB callback.
- **New in v3.4**: AI and agent exposure — MCP servers, agent admin panels, unauthenticated model endpoints, **passive detection only**. Finding a server is passive; reading its admin panel is not, and the AI-exposure checks must each carry their own `passive` declaration under 0b.6 rather than inherit one from the mode.
- Mechanism: crawler (ZAP's, Apache-2.0, to start — **[v2 said]** Nuclei for template checks; ZAP crawler as a stopgap → still the plan, unchanged), own injection engine, own content-discovery engine, web-archive APIs, OOB callback client.
- **Status: Not built.** Blocked on: HTTP record/replay (**done**, 0b.4) and the OOB callback server (Phase 2a, not built).
- **Gate:** precision ≥ 0.90 overall (`confirmed` ≥ 0.98), recall ≥ 0.75 on the benchmark tier, inconclusive ≤ 0.15, ≥ 0.95 of blind-class findings proven via OOB. Recall is **benchmark-true, corpus-relative elsewhere** — never publish it as absolute for Light.
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
- **Status: Shipped.** 13 checks (Standard), gate met.
- **Gate:** precision ≥ 0.98, recall ≥ 0.95, inconclusive ≤ 0.15. **Actual, from `make corpus` (2026-09-01):** `precision 1.000, recall 1.000, susp% 6.0%, inconc% 0.0%, PASS` — 134 checks run, **5 claims** (`confirmed`/`highly_likely`). Read the claim count with the number: most findings land as `suspected` (honest — one `independence_class` — and excused from the gate on both sides), so 1.000 rests on five claims, not 134.
- **Caveats that belong here, not buried:** 14-case corpus, cross-checked against testssl.sh. Six real defects across Tools 1 and 2 survived their corpora at precision 1.000 — three of the six were in the TLS lab itself (a CA missing `basicConstraints`, servers accepting TLS 1.0, a two-level chain standing in for an incomplete one), found only by reading the fixtures, not by the harness. Certificate revocation checking (OCSP/CRL) is not built — `revoked.badssl.com` currently returns nothing, which reads as a pass (D12). No weak-cipher (`RC4`/`3DES`) positive case exists; OpenSSL 3 compiles them out (D11).
- Depends on: HTTP record/replay for HSTS (done, 0b.4).

### A4. Domain & Subdomain Enumeration — Tool 3, next

One-line: the asset list every other tool scans, plus subdomain-takeover detection.

- **Light** — subdomains from CT logs and passive DNS, all DNS record types, WHOIS/RDAP, nameservers, DNSSEC, domain expiry.
- **Standard** — active brute-force, liveness check, tech-per-subdomain, subdomain takeover, AXFR misconfig check, wildcard DNS detection, related-domain discovery, OSINT harvesting, shadow IT discovery.
- Mechanism: subfinder, dnsx, httpx, Amass (all approved permissive licences) for Standard; own takeover-fingerprint list.
- **Status: Not built.** Named next in the ledger's "what to do next."
- **Gate:** precision ≥ 0.95, recall corpus-relative and **never published as absolute** — "all subdomains that exist" is not a knowable set ([docs/10-measurement.md](docs/10-measurement.md)). Settling the recall definition is explicitly called out as owed before any code is written.
- Depends on: asset graph (0b.2, done) — this is the tool the graph mechanism exists for; it discovers assets onto the shared graph rather than reading one seeded for it.

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
- **Status: Shipped.** 17 checks, gate met.
- **Gate:** precision ≥ 0.99, recall ≥ 0.95, inconclusive ≤ 0.15. **Actual, from `make corpus` (2026-09-01):** `precision 1.000, recall 1.000, susp% 0.0%, inconc% 0.8%, PASS` — 240 checks run, **21 claims**.
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

Verified against the repo and `make corpus` (2026-09-01) — see the run at the end of this document.

| Tool / Feature | Status | Gate | Actual (where shipped) |
|---|---|---|---|
| A1 Website Scanner | Not built | precision ≥0.90 (`confirmed`≥0.98), recall ≥0.75 (benchmark) | — |
| A2 Network Scanner | Not built | not yet set | — |
| A3 SSL/TLS Analyzer | **Shipped** | precision ≥0.98, recall ≥0.95, inconc ≤0.15 | 1.000 / 1.000, 134 checks, 5 claims, 0.0% inconc, PASS |
| A4 Domain & Subdomain Enum | Not built (next) | precision ≥0.95, recall corpus-relative | — |
| A5 Deface Monitoring | Not built | not yet set | — |
| A6 API Scanner | Not built | not yet set | — |
| A7 Email Security | **Shipped** | precision ≥0.99, recall ≥0.95, inconc ≤0.15 | 1.000 / 1.000, 240 checks, 21 claims, 0.8% inconc, PASS |
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

**`make corpus` output used for this table (2026-09-01):**

```
scanner     checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
----------------------------------------------------------------------------
email          240   21    0    0      1.000    1.000   0.0%    0.8%  PASS
           recall is absolute (the true set is knowable for this scanner)
example          3    2    0    0      1.000    1.000   0.0%    0.0%  PASS
           recall is absolute (the true set is knowable for this scanner)
tls            134    5    0    0      1.000    1.000   6.0%    0.0%  PASS
           recall is absolute (the true set is knowable for this scanner)
```
