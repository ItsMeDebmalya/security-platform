# 03 — Roadmap

*Phase by phase. Each phase has an exit criterion you can check objectively. Do not start a phase before the previous one's exit criterion is met.*

---

## Overview

| Phase | Name | Rough time | What exists at the end |
|---|---|---|---|
| **0** | Foundations | **3–4 weeks** | A skeleton that runs a trivial scanner end to end |
| **0b** | Foundation for the calendar | — | Dated and derived findings, the asset graph, one record/replay layer, per-check passivity, the calendar, the finding store and `scan verify`, the correlation pass |
| **1** | The cheap accurate tools | 4–6 weeks | 4 scanners, each passing its accuracy gate |
| **2** | The hard one | **5–8 months** | OOB server + Website Scanner Standard (descoped) |
| **3** | Breadth | 8–10 weeks | Network, API, monitoring, replay, imports |
| **3a** | IoT & Device Security | — | Device exposure (5a), then device vulnerability (5b) |
| **4** | Intelligence | 6–8 weeks | Confidence calibration, correlation, scores, reports |
| **5** | Depth tools | 10–14 weeks | Code, container, cloud, supply chain, LLM |
| **6** | The site | 10–14 weeks | The actual product users log into |
| **7** | Enterprise | ongoing | SSO, RBAC, residency, MSSP, mobile |

Phases 0–5 are terminal-only. **Nothing has a user interface until Phase 6.** That is deliberate — see [ADR-001](02-decisions.md#adr-001--build-tools-first-platform-second).

**Ordering principle within phases:** cheapest-and-most-deterministic first. Tools with near-zero false-positive rates prove the harness works before we take on tools where accuracy is genuinely hard.

> **v3.1 re-estimate.** Phase 0 and Phase 2 were both materially underestimated in the first draft and have been revised upward — Phase 2 by roughly 3x after comparison with how long ZAP, Nuclei and Burp took to reach acceptable quality on the same problems. Phase 2's scope has also been cut. Total to a paid site is now **18–24 months**, not 12–18. See [08-changelog.md](08-changelog.md).

**All accuracy gates below are computed per [10-measurement.md](10-measurement.md)** — precision and recall over `confirmed`+`highly_likely` only, plus an inconclusive-rate ceiling of 15%. A gate is not passed without all three.

---

## Phase 0 — Foundations

**Goal:** the shared skeleton, so that tools built one at a time still fit together.

- Repository layout, dependency management, CI
- **The Scanner Contract** — finding / scan-result / evidence schemas, `BaseScanner`, `ScanContext`
- `core/` services: HTTP client, DNS client, rate limiter, kill switch, scope enforcement, evidence capture with redaction, cost meter
- The `scan` CLI: `scan <tool> --target <t> --mode <m> --out result.json`
- Corpus harness: run a scanner against ground truth, report precision/recall, fail CI on regression
- Tool registry: every third-party binary with pinned version, licence, and sign-off
- One trivial reference scanner (`scanners/example`) proving the whole loop

**Exit criterion:** `scan example --target example.com --mode light` emits schema-valid JSON, and `make corpus` reports precision, recall and inconclusive rate for it. Full task list: [04-phase-0-foundations.md](04-phase-0-foundations.md).

---

## Phase 0b — Foundation for the calendar *(new in v3.4)*

**Goal:** make the foundation carry the four claims in [ADR-020](02-decisions.md#adr-020--amends-adr-014-what-we-claim-now-that-the-ground-has-moved) before more scanners are built on top of it. Two scanners exist today; ten would make every item here a migration instead of an edit.

| # | Work | Why it is here and not later |
|---|---|---|
| 0b.1 | **Dated and derived findings** — `materialises_at`, `derivation`, `derived_from` ([ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived)) | The deprecation clock has nowhere to live without it. Today's finding schema has no notion of a future date, and `severity` means "how bad if true" — a 200-day certificate is not bad *yet*, so it would have to be filed as `info`, which the gate excludes entirely. The flagship feature would not count toward any accuracy number. |
| 0b.2 | **The asset graph** ([ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other)) | "DNS enumeration feeds every other tool" has been in the roadmap since v3 with no mechanism. Tool 3 is next and *is* the pipeline; deciding its output shape after writing it is the expensive order. |
| 0b.3 | **Generic record/replay in `core/`** | Written twice already — `core/dns.py` and `core/tls.py` each hand-rolled fixture naming, backends and a missing-fixture error, sharing no code. HTTP, MCP and any device protocol are next. Three times is a pattern; five is a liability. |
| 0b.4 | **HTTP record/replay** (was D2) | No longer a Tool 4 detail. It blocks HSTS, all AI-exposure work, and most device surfaces. The largest single unblock in the deferred register. |
| 0b.5 | **Toolchain upgrade** — Python 3.13, OpenSSL 3.5.7, crypto build pinned | **Done 2026-08-28, premise corrected.** The original row here claimed 3.13 unblocks post-quantum key exchange. Measured directly: `set_groups`/`get_groups`/`SSLSocket.group()` arrive in Python **3.15** (currently rc1), not 3.13 — post-quantum detection is still blocked, now on 3.15 final rather than on 3.12. See D16. 3.13 is still worth taking: `get_unverified_chain` does land there, and OpenSSL goes from 3.0.13 to 3.5.7. Results depend on the OpenSSL build, so it is pinned via `.python-version` (3.13.15) or corpus numbers are not reproducible across machines. |
| 0b.6 | **Passivity declared per check, not per mode** | Hit twice already: every email Standard check is passive but sits behind the ownership gate anyway. For AI exposure the line is one HTTP request wide — finding a server is passive, reading its admin panel is not. The gate should enforce a declaration, not trust the author's filing. |
| 0b.8 | **Finding store + `scan verify`** ([ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target)) | "We check your fix worked" has been a differentiator since v2 with nothing behind it. It needs findings to persist between scans and a re-test operation. The contract already has `status`, `status_history` and `first_seen`/`last_seen_scan_id`; what is missing is the store and the operation that drive them. |
| 0b.9 | **Correlation pass + composition rules** ([ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target)) | Turns a list of findings into attack stories, and "fix these first" falls out. Runs after all scanners, reads the asset graph, imports no scanner, emits `derived` findings. Rules are curated data, like the calendar. |
| 0b.7 | **The deprecation calendar as curated data** | Deadlines are versioned, sourced, reviewed data with a lifecycle — not constants in code. A rotted clock asserts wrong dates in our name, which is worse than not shipping one. |

**Exit criterion:** a scanner can emit a dated, derived finding whose confidence is inherited from its premise; a scanner can read assets another scanner discovered; one `core/` recording layer serves DNS, TLS and HTTP; a scanner can re-verify a single finding and transition its status with fresh evidence; and a run can connect related findings into one story with inherited confidence.

---

## Phase 1 — The cheap, accurate tools

**Goal:** four real scanners. Prove the contract survives contact with reality, and that we can hit accuracy gates.

| # | Tool | Why this order | Gate (Light) |
|---|---|---|---|
| 1 | **Email Security** | Pure DNS, deterministic, near-zero FP rate, most companies fail it. The ideal first tool — if we cannot get this to 99% precision, nothing else will work. | precision ≥ 0.99, recall ≥ 0.95 |
| 2 | **SSL/TLS Analyzer** | Cheap, accurate, builds trust fast. badssl.com is a ready-made ground-truth corpus. | precision ≥ 0.98, recall ≥ 0.95 |
| 3 | **DNS & Subdomain Enumeration (Light)** — `domscout`, **shipped** (live cross-check owed) | Feeds every other tool — it produces the asset list everything else scans. Includes dangling-CNAME subdomain-takeover (passive, Light). The recall target binds the **security findings**, not subdomain discovery — see below. | precision ≥ 0.95, recall ≥ 0.80 (security findings) |
| 4 | **Website Scanner (Light)** | Passive only: headers, cookies, tech fingerprint, directory listing, info disclosure. No payloads sent. | precision ≥ 0.95, recall ≥ 0.85 |

Recall for **Web Light is corpus-relative, not absolute** — "all header misconfigurations on a site we don't fully understand" is not a knowable set. **For DNS enumeration the question was settled differently (Tool 3, 2026-09-03):** subdomain *discovery* is informational inventory, not a vulnerability, so it is **not** confidence-scored or recall-gated at all — its completeness is assessed live against subfinder/crt.sh as a comparison, never a published number. The recall gate for `domscout` therefore binds only its **security findings** (DNSSEC/expiry/takeover), whose per-domain answers are knowable. Any published number must state which kind it is; see [10-measurement.md](10-measurement.md). Email and TLS have genuinely finite check surfaces, so their recall is true recall.

**Changed in v3.4.** Tool 2 gains a **v1.1**: certificate lifetime readiness and post-quantum exposure — the first two dated findings, on a scanner that already passes its gate. Tool 4's scope widens from "passive website checks", which every competitor has, to include **AI and agent exposure** — the same crawling machinery pointed at a surface nobody has productised. Tool 3 keeps its position: it is the asset discovery that makes Tool 4's new half possible at all.

**Also in this phase:** payload library v1 structure (even though Light modes send no payloads, the format and versioning are established now), and the technology fingerprint database v1.

**Exit criterion:** all four pass their gates in CI; a single command runs all four against a domain and produces one merged, deduplicated `ScanResult`. Full task list: [05-phase-1-first-tools.md](05-phase-1-first-tools.md).

---

## Phase 2 — The hard one

**Goal:** the flagship. This is where the product is won or lost — and where the first draft of this plan was most wrong about cost.

> **Re-estimated 8–12 weeks → 5–8 months, and descoped.** The original scope bundled a JS-rendered crawler, content discovery, historical URL mining, seven injection classes including DOM and stored XSS, a validation engine and backport-aware CVE matching, gated at precision ≥0.90. For comparison: OWASP ZAP has had 16 years and still trails Burp Pro specifically on DOM XSS and blind-injection false-positive rates. Any one of those sub-items is plausibly a multi-month task for one or two people.

**2a. Out-of-band callback server** *(build or adopt first — [ADR-008](02-decisions.md#adr-008--build-the-out-of-band-callback-server-before-standard-web-scanning))*
- **First decide build vs self-host Interactsh** (MIT, self-hostable, all four protocols, same team as our other approved tools). Do not write a Go service from scratch before evaluating this.
- Separate domain; answers DNS / HTTP / HTTPS / SMTP; single-use scan-scoped expiring tokens; hit log is the evidence
- **One wildcard cert via DNS-01**, renewed ~60-daily. Never a cert per token — that hits Let's Encrypt limits immediately.
- Client library in `core/`; scanners must degrade to `inconclusive` when it is unavailable, never crash

**2b. Crawler** — Playwright/Chromium, JS-rendered pages, forms and parameters, scope-bounded, session-aware. **Start from OWASP ZAP's crawler (Apache-2.0, already approved) rather than building Playwright orchestration from scratch** — the original plan floated this and then ignored it. Budget ~3–4 concurrent browser contexts per host, raise `/dev/shm` explicitly in the container spec, and treat context-leak prevention as a first-class task.

**2c. Content discovery engine** — ffuf-style logic integrated *with* the crawler. Curated wordlists. Correct wildcard/soft-404 handling is the hard part.

**2d. Historical URL mining** — web archive APIs, then liveness-check. Cheap, finds forgotten endpoints.

**2e. Injection testing engine — descoped to the deterministic classes.**

| In scope for Phase 2 | Deferred to Phase 2.5 |
|---|---|
| Reflected XSS | **DOM XSS** — among the hardest DAST problems; Burp still leads ZAP here after a decade |
| SQL injection (error, boolean, time-based) | **Stored XSS** — requires multi-step state tracking across the crawl |
| Open redirect | |
| CORS misconfiguration | |
| Path traversal / LFI | |
| SSRF **via OOB callback** | |

**2f. Validation engine** — the second pass that turns `suspected` into `confirmed` using an independent method.

**2g. CVE matching with backport detection.** **Prerequisite the original plan omitted: OS/distro fingerprinting.** A banner reading `Apache/2.4.41` does not say who packaged it, and you cannot query the right distro security tracker without knowing. Budget this explicitly. It also does nothing for software not packaged by a distro — there the version string genuinely is the only signal, and the ≤0.6 confidence cap is the only mitigation.

| Gate | Target |
|---|---|
| Website Scanner Standard, precision | ≥ 0.90 (with `confirmed` findings ≥ 0.98) |
| Website Scanner Standard, recall (benchmark tier) | ≥ 0.75 |
| Inconclusive rate, frozen tier | ≤ 0.15 |
| Blind-class findings proven via OOB | ≥ 0.95 of those detected |

**Exit criterion:** Standard scan against the **benchmark tier (OWASP Benchmark + WAVSEP)** plus Juice Shop and DVWA hits the gate above, with replayable evidence for every `confirmed` finding and zero findings on the known-good tier.

---

## Phase 3 — Breadth

**Goal:** the tools users expect to see on the menu, plus the retention features.

| Tool / feature | Notes |
|---|---|
| **Network Scanner** | naabu for discovery + our own service fingerprinting. Never Nmap ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves)). Backport-aware CVE matching. |
| **API Scanner** | Our biggest technical differentiator. Real **BOLA/BFLA** testing needs a session manager holding **two identities at once** — log in as A, create an object, try to read it as B. Most competitors just point a web scanner at an API URL. Also: JWT weaknesses, mass assignment, excessive data exposure, GraphQL depth abuse, spec drift. |
| **Attack Surface Monitor** | Continuous diff over discovered assets: new subdomain, new port, cert expiring, tech version changed, new CVE affects your stack. Commercially the single most important item — it converts one-time scans into subscriptions. |
| **Deface / change monitoring** | Baseline + diff. The hard part is *ignoring* legitimately-changing content (timestamps, ads, tokens) so alerts stay trustworthy. |
| **Request Replay** | "Burp Repeater in our UI." Nearly free once evidence is replayable. Scope- and rate-limited identically to a scan. |
| **Canary Tokens** | Reuses the Phase 2a server. Low effort, genuine value. |
| **OSINT harvesting** | Public emails, names, hosts tied to a domain. |
| **Import from other scanners** | [ADR-010](02-decisions.md#adr-010--import-findings-from-the-tools-we-cannot-embed). Mostly parsing. Imported findings marked unverified. |
| **Third-party / vendor risk** | Light Scan against a user's suppliers + a rating. Reuses everything; near-zero new engineering. **Passive only** — the user does not own these domains. Legally important. |

---

## Phase 3a — The IoT & Device Security Scanner *(new in v3.4)*

**Goal:** the headline differentiator. A distinct tool, not a check family — see [ADR-021](02-decisions.md#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family) and the full plan in [15-iot-scanner.md](15-iot-scanner.md).

| Tool | Gate | Depends on |
|---|---|---|
| **5a — Device Exposure** | precision ≥ 0.95, recall corpus-relative | Protocol clients in `core/`, record/replay (0b.3). **Not** port discovery — it probes the dozen known device ports directly on an authorised range. |
| **5b — Device Vulnerability** | precision ≥ 0.90, recall corpus-relative | 5a, plus identification and a CVE source |

**The claim:** *the scanner you can safely point at fragile devices, that tells you which vulnerabilities it actually confirmed and says "I do not know" when it cannot tell.* Existing tools are either passive and expensive or aggressive and dangerous; **our no-exploitation rule becomes a feature here** rather than a limitation.

**Why 5b's gate is lower than every other tool's.** It infers from a firmware string rather than observing. An unreachable target would push an author to under-report; the honest instrument is a lower gate plus a mandatory detected/derived split.

**5a could be pulled forward.** Its only hard dependencies are Phase 0b items. Placing it before the Network Scanner trades roadmap tidiness for having the differentiator sooner — a live decision, not a settled one.

**Safety is stop-the-line here.** Devices break in ways servers do not, and what breaks may be doing something physical. The rate ceilings in [06-guidelines.md](06-guidelines.md) are floors, not defaults.

---

## Phase 4 — Intelligence

**Goal:** turn a list of findings into an answer to "what do I fix first?"

- **Confidence calibration loop** — by now we have labels from corpus runs and manual verification. Fit the calibration map, publish reliability diagrams and Brier score per scanner. This is when confidence numbers stop being provisional.
- **Basic finding correlation** — group related findings about one asset into a single story ("this cert + this subdomain + this open port"), driven by the `related_assets` field. Deliberately modest.
- **~~Chokepoint analysis~~ — cut as a differentiator ([ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own)).** It is Wiz's and XM Cyber's core product, and it depends on an IAM/resource graph that does not exist until Phase 5's Cloud CSPM — a Phase 4 item secretly depending on Phase 5. Revisit only after CSPM ships, if ever.
- **The attack-path data model is an open question**, not a solved one. It must be validated by the end of Phase 3, before any Phase 4 correlation work starts.
- **Fix verification** — re-run the exact proving test, close with evidence. Always free.
- **Security score** — 0–100 plus sub-scores. **Rule: every score must be clickable down to the exact findings that caused it.** An unexplainable score destroys trust with technical users.
- **Reporting** — executive summary, full technical, developer-focused, change report, evidence pack. Export CSV/JSON/SARIF.
- **AI assistant** — explain a finding to a developer / a manager / an auditor; answer questions grounded in *our actual evidence*, never freestyling; "what should I fix first and why"; "why did my score change."
- **Learning content** — plain-language explanation per vulnerability class, how attackers use it, secure-coding examples.

---

## Phase 5 — Depth tools

Each is a substantial scanner in its own right. Order by demand, not by this list.

| Tool | The thing that makes it worth doing |
|---|---|
| **Supply Chain Scanner** | **Reachability analysis is cut ([ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own))** — it is Endor Labs' entire product and a pillar of Semgrep Supply Chain; a single-language MVP is 3–6 months and would still be visibly worse. Ship direct-dependency CVE matching via OSV.dev instead, using direct-vs-transitive as a crude noise proxy, and say plainly that we do not do reachability. |
| **Code Scanner (SAST + secrets)** | Opengrep + **our own rule corpus** (never Semgrep's rules). **Live secret validation** — worth an order of magnitude more than "this looks like a key", but it is an integration programme, not a feature: TruffleHog's actual moat is 800+ verifiers built over years. Scope to the **top 15–20 providers** (AWS, GCP, Stripe, GitHub, Slack, SendGrid, npm/PyPI…), framed as permanently ongoing. **Per-provider ToS review required** — some treat any unauthorised auth attempt as abuse regardless of intent. Clone into an isolated sandbox. |
| **Container Scanner** | Trivy/Syft/Grype do most of it. **Reachability filtering is mandatory** — one base image yields 500+ CVEs, mostly unexploitable. Without filtering this tool is noise and users will ignore it. |
| **Cloud CSPM** | Prowler for breadth. **Do not compete with Wiz on breadth.** Our angle is narrow: link what we see outside to what we see inside — "this exposed subdomain points to this instance, which has this role, which can read this bucket." Read-only config; never scan running workloads. |
| **AI/LLM Scanner** | garak + PyRIT + our own prompt corpus. Report as a **success rate over N attempts**, not yes/no — these attacks are probabilistic, and reporting them honestly is itself a differentiator. Timing window closes in roughly 18 months. |
| **Compliance readiness** | Map findings to SOC 2 / ISO 27001:2022 / PCI DSS 4.0.1 / GDPR Art.32 / HIPAA / NIST CSF 2.0. Always "readiness" ([ADR-011](02-decisions.md#adr-011--compliance-readiness-never-compliance)). |
| **Credential exposure monitor** | Licensed provider only; **legal review required before building**. Never scrape criminal marketplaces or buy stolen data. |

---

## Phase 6 — The site

**Goal:** wrap the shelf. If Phase 0 was done properly, `scanners/` is not touched in this phase.

- API over the same operations the CLI exposes
- Queue + stateless workers, sandboxed with restricted egress
- Postgres (every row carries `org_id` from migration #1), object storage for evidence
- Accounts: email / Google / GitHub. **Light Scan on any domain with no signup** — the major conversion driver.
- **Asset ownership verification** — DNS TXT, file upload, HTML meta tag, or email. Gates every Standard scan. Legal requirement, not a feature.
- Scan management: on-demand, scheduled, live progress, pause/stop, history, compare two scans, re-scan one finding
- Findings management: one prioritised list across all tools and assets; filter by severity/confidence/state/asset/tool/framework/age; group by root cause; false-positive marking **with a reason** (this feeds calibration); accept-risk with expiry and approver; owner; comments; full status history
- Billing: Free / Pro / Business tiers, daily credits that refresh and do not accumulate, usage dashboard, warning at 80%, **hard stop rather than surprise billing**
- Alerts and integrations: email, Slack, Teams, webhook, PagerDuty; Jira, Linear, GitHub Issues, ServiceNow; GitHub/GitLab/Bitbucket; CI/CD; SIEM export; REST API; CLI

---

## Phase 7 — Enterprise

SSO (SAML/OIDC), granular RBAC (Owner / Admin / Engineer / Auditor / Viewer), per-project permissions, audit log, data retention settings, data residency, internal network scanning, mobile scanner, MSSP multi-client platform and white-labelling.

---

## What moved, versus the original v2 plan

Recorded so the change is visible and reversible. Full detail and revert instructions in [08-changelog.md](08-changelog.md).

| Item | v2 | Now | Why |
|---|---|---|---|
| Website Scanner | Priority 1, first thing built | Phase 2, after four easier tools | Highest-risk, hardest-to-verify tool. Prove the harness on deterministic tools first. |
| Platform / accounts / billing | Phase 1, parallel with scanners | Phase 6 | [ADR-001](02-decisions.md#adr-001--build-tools-first-platform-second) |
| Scanner Contract + corpus harness | Not present | Phase 0, before any tool | The mitigation for tool-first's failure mode |
| OOB callback server | Priority 7 | Phase 2a, before Standard web scanning | Standard mode cannot prove blind bugs without it |
| Confidence calibration | Priority 6 ("confidence engine") | Split: schema in Phase 0, provisional priors in Phase 1, **calibration in Phase 4** | Calibration needs labels, and labels need scans to have happened |
| AI assistant | Priority 8 (Phase 1) | Phase 4 | Nothing to explain until findings with evidence exist |
| Free/Pro tiers, credits | Priority 9 (Phase 1) | Phase 6 | No site to sell from |
| Timeline to launch | ~4–5 months | **18–24 months** to a paid site (v3 said 12–18; revised in v3.1 after Phase 2 was re-estimated) | The v2 estimate assumed the platform *was* the launch. Accuracy-gated tools take longer and are worth more — and the flagship scanner is a far bigger job than either estimate allowed. |
