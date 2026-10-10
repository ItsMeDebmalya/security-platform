# 02 — Decisions (ADRs)

*Every significant decision, why it was taken, what it costs to reverse. If you disagree with something here, this is the file to argue with — not the code.*

Status values: **Decided** · **Provisional** (decided but low-confidence, revisit at a named trigger) · **Open** (see [07-open-questions.md](07-open-questions.md))

| # | Decision | Status | Reversal cost |
|---|---|---|---|
| 001 | Tool-first build order | **Superseded** by [026](#adr-026--adopt-api-first-architecture-supersedes-adr-001-tool-first-and-adr-012-platform-deferral) | Low |
| 002 | Freeze the Scanner Contract before tool #1 | Decided | Very high once tools exist |
| 003 | Permissive-OSS-or-build-it-ourselves | Decided | Very high (legal) |
| 004 | No exploitation, ever | Decided | Not reversible — product identity |
| 005 | Python for the harness and most scanners | Provisional | Medium |
| 006 | Ground-truth corpus gates every scanner | Decided | Low |
| 007 | Confidence separate from severity | Decided | High (schema + UI) |
| 008 | Build the OOB server before Standard web scanning | Decided | Medium |
| 009 | Postgres + queue + object storage for the platform | Provisional | Medium |
| 010 | Import findings from commercial scanners | Decided | Low |
| 011 | Compliance *readiness*, never "compliance" | Decided | Not reversible — legal |
| 012 | Defer all platform/billing work to Phase 6 | **Superseded** by [026](#adr-026--adopt-api-first-architecture-supersedes-adr-001-tool-first-and-adr-012-platform-deferral) | Low |
| 013 | Measurement spec: gates are precision + recall + inconclusive rate | Decided | Low |
| 014 | Descope the moat claims to what 2 people can own | Decided | Low |
| 015 | Ownership verification exists from tool #1, not Phase 6 | Decided | Not reversible (legal) |

> **v3.1:** every factual claim in ADR-003 was checked against primary sources. Corrections are marked **[verified 2026-08]** or **[CORRECTED]** inline. Claims that could not be verified are marked **[UNVERIFIED]** rather than left to look settled.

---

## ADR-001 — Build tools first, platform second

> **Superseded by [ADR-026](#adr-026--adopt-api-first-architecture-supersedes-adr-001-tool-first-and-adr-012-platform-deferral) (2026-10-02).** The v4 plan replaces tool-first with API-first. The text below is kept unchanged as the historical record of why tool-first was chosen.

**Decision.** Build and prove scanners one at a time as standalone CLI tools. Build the website only after a shelf of them exists and passes accuracy gates.

**Context.** The original v2 plan ran platform and flagship scanner in parallel toward a 4–5 month launch. We are a small team whose entire differentiation is accuracy.

**Reasoning.**
- Accuracy is the product. A UI wrapped around unproven results is a liability, not progress.
- CLI iteration is seconds; UI iteration is minutes. Over thousands of test runs that difference dominates the schedule.
- Defers every expensive and reversible-only-at-cost decision (framework, hosting, payments, auth) until the platform's real requirements are known.
- Partial completion still has value: working tools.

**Costs we accept.** No revenue and no real user feedback until Phase 6. Risk of building the wrong thing well.

**Trigger to revisit.** If we reach the end of Phase 2 and still have no external validation that anyone wants this, cut Phase 3–5 scope and jump to Phase 6 with the four Phase 1 tools. Tracked in [07-open-questions.md](07-open-questions.md) Q1.

**Reversal cost.** Low. The Scanner Contract (ADR-002) exists precisely so the platform can be built at any time without touching scanners.

---

## ADR-002 — Freeze the Scanner Contract before writing tool #1

**Decision.** The finding schema, scan-result shape, evidence format and `BaseScanner` interface are defined and frozen in Phase 0. Every scanner satisfies them exactly.

**Reasoning.** ADR-001's known failure mode is a pile of tools that do not fit together. The contract is the entire mitigation. It is roughly a week of work and it converts "rewrite everything when the site arrives" into "the site is a thin wrapper."

**Consequences.**
- Contract changes after Phase 1 require migrating every scanner and every stored finding. Treat as a database migration: versioned, reviewed, with a written migration path.
- `scanner_version` is on every finding so results from different engine versions remain comparable.
- Scanners never construct their own HTTP/DNS clients — ambient services come from `ScanContext`, which is how rate limiting and the kill switch stay guaranteed.

**Reversal cost.** Very high once tools exist. This is the decision to get right.

---

## ADR-003 — Permissive open source, or we build it ourselves

**Decision.**

> If a tool is free and open source with a permissive licence, we use it.
> If a tool is commercial, restrictively licensed, or legally unclear, we do not embed it. We build our own version, and we offer to import that tool's results instead.

**Reasoning.**
- **Legal safety** — no licence violation exposure, no enforcement letters.
- **Unit economics** — commercial per-seat/per-target/OEM licences scale with usage and would push us below our ~75% gross-margin target at the Business tier, forcing prices up into the range where enterprise vendors already compete. That is exactly the market we are avoiding.
- **Accuracy ceiling** — depending on someone else's engine caps our accuracy at their accuracy. Accuracy is our whole thesis, so it cannot be outsourced.
- **IP** — every engine we build is an appreciating asset; every tool we rent is a cost that grows with usage.

### Approved for use

| Tool | Licence | Used for |
|---|---|---|
| Nuclei | MIT | Template-based checks (pin 3.8.0+) |
| naabu | MIT | Port scanning — our Nmap replacement |
| subfinder | MIT | Passive subdomain enumeration |
| dnsx | MIT | DNS resolution and brute-force |
| httpx | MIT | Live host probing and metadata |
| Amass | Apache-2.0 | Deep asset discovery (Standard only — slow). **[UNVERIFIED: recent maintenance health]** |
| Gitleaks | MIT | Secret detection in code |
| Trivy | Apache-2.0 | Container, IaC, dependency scanning |
| Syft / Grype | Apache-2.0 | SBOM generation / vulnerability matching |
| Checkov / KICS | Apache-2.0 **[not re-verified]** | Infrastructure-as-Code scanning |
| Prowler | Apache-2.0 | AWS / Azure / GCP posture checks |
| Opengrep | LGPL-2.1 | SAST engine — **not Semgrep**. [verified 2026-08: consortium-backed, ~10 companies, actively developed] |
| garak | Apache-2.0 | LLM vulnerability probing **[UNVERIFIED: production maturity not confirmed]** |
| PyRIT | MIT | Adversarial LLM testing **[UNVERIFIED: production maturity not confirmed]** |
| MobSF | **GPLv3** | Mobile static analysis — **separate service only**, see GPL note |
| OWASP ZAP | Apache-2.0 | Optional crawler, early versions only |
| testssl.sh | GPLv2 | TLS analysis — **separate process only** |
| OSV.dev | Free API | Vulnerability database |
| Certificate Transparency | Public data | Subdomain and cert discovery |

### Forbidden, and what we build instead

| Tool | Why not | What we build | Import its results? |
|---|---|---|---|
| **Nmap** | NPSL forbids inclusion in a proprietary product, appliance, VM **or container**, without an OEM licence. [verified 2026-08 against nmap.org/npsl/npsl-annotated.html] | naabu + our own service fingerprinting — **see the capability note below** | Yes — Nmap XML |
| **Nessus** | Commercial. Per-scanner cost destroys margin. | Our network vuln engine — naabu discovery + CVE matching with backport detection | Yes — `.nessus` |
| **Burp Suite** | Commercial; almost certainly forbids use inside a competing product. | Our web engine — Playwright crawler, injection engine, content discovery | Yes — Burp XML |
| **Acunetix / Invicti** | Commercial, expensive per-target | Same — our own DAST | Yes |
| **Semgrep rules** | Rule licence changed Dec 2024 — no competing-SaaS use | Opengrep engine + our own rule corpus | Yes — SARIF |
| **TruffleHog** | AGPL-3.0 — can require publishing our source | Gitleaks + our own live credential validator | Not needed |
| **OpenVAS / Greenbone** | Community feed terms unclear for commercial service use; heavy and slow | Our own network CVE matching | Yes, if a customer has it |
| **Qualys / Rapid7 / Snyk** | Commercial platforms, not embeddable | Our equivalents per area | Yes |
| **Metasploit** | **Safety**, not licence — runs real exploits that change system state | OOB callback proof | No |

**The naabu gap — do not read the table above as claiming parity.** naabu is a **port scanner only**: SYN/CONNECT scanning and host discovery. It ships no service or version detection. Nmap's `nmap-service-probes` is roughly 12,000 signatures accumulated over twenty years. "Plus our own service fingerprinting engine" was one bullet in the original plan covering a multi-month, permanently-ongoing effort.

We scope it honestly instead: a **service fingerprinting corpus v1 covering the top ~50 services**, gated on the corpus like any other detection, with no claim of Nmap parity — now or later. Anything outside that set returns `inconclusive` rather than a guess.

**GPL handling.** GPL tools run as a **separate process** only. Never link, never copy GPL code into our tree. Enforced in code review and by a CI check (see [06-guidelines.md](06-guidelines.md)).

The GPL tools are **testssl.sh (GPLv2), ScoutSuite (GPL), and MobSF (GPLv3)**.

**[CORRECTED]** MobSF was previously listed here as plain "open source" alongside the MIT/Apache tools, with no isolation requirement. It is GPLv3. It is also a Django application, not a CLI binary — so "separate process" means **standing it up as its own containerised service and talking to it over its HTTP API**. Importing its Python modules would be a licence violation. The CI GPL check must cover it.

**Fingerprint data is a licence surface too.** Wappalyzer went closed-source in August 2023; its pre-close fingerprint database and the community forks that carry it are **GPL-3.0**. "Wappalyzer-style" describes our *approach* — pattern matching on headers, cookies and markup. It does not license their data. Fingerprint signatures must be authored from our own observation and public documentation, never copied or adapted from those files, which are widely mirrored and extremely tempting to bootstrap from.

**Other data-licence traps to check before use:** Nuclei's templates are licensed separately from the Nuclei engine; SecLists and other wordlists carry their own terms; the GitHub Advisory Database is CC-BY-4.0 and carries attribution requirements. None of these were verified in the original plan.

Long term, replace testssl.sh with our own implementation for speed anyway.

**Reversal cost.** Very high — this is a legal posture, and an embedded commercial tool discovered late means removing it and rebuilding under time pressure.

---

## ADR-004 — No exploitation, ever

**Decision.** We never run code on a customer's system, never change system state, never extract real data.

**Excluded, with reasons:**

| Excluded | Why |
|---|---|
| Reverse shells | Running code on the customer's server. Can break production, can touch real data, and it is the line between testing and hacking. |
| Metasploit-style exploitation | Changes system state. Legal and safety risk. |
| Password brute-force / spraying | Locks out real user accounts. Enterprise-only under separate contract, if ever. |
| Data extraction (sqlmap dump mode) | We prove injection exists; we never pull out real data. |
| DDoS / load testing | Destructive by definition. Never. |
| Breach & Attack Simulation | Different product; needs agents inside the network. |
| SIEM / log monitoring | Different product. We integrate instead. |
| EDR / endpoint agents | Different product, huge support burden. |
| Phishing simulation | Involves real employees; separate legal and consent framework. |

**What we do instead.** Out-of-band callbacks and canary tokens. To prove SSRF we do not open a shell — we make the target request a unique URL only we control. If our server is hit, the bug is proven with certainty and nothing was touched.

> *We prove the door is unlocked. We never walk in and rearrange the furniture.*

This is the approach serious autonomous testing platforms take. It is a selling point, not a limitation, and it must be phrased that way in sales material.

**Amended by [ADR-025](#adr-025--authorized-exploitation-deep-tier-only-opt-in-per-scanner).** The default above is unchanged and remains the identity: no exploitation, ever, in Light and Standard, and never at all for the IoT scanner or for anything that changes state or extracts data. ADR-025 carves one narrow, gated exception — controlled exploitation in Deep/Validated mode, only under a signed authorization agreement, only where a finding cannot be proven any safer way. It does not soften this ADR; it defines the single place this ADR does not reach.

**Reversal cost.** Not reversible. It is the product's identity and its legal defensibility.

---

## ADR-005 — Python for the harness and most scanners *(Provisional)*

**Decision.** Build `core/`, the CLI and the scanners in Python 3.12+. Use the Go security tools as **pinned binaries invoked as subprocesses**, not as libraries.

**Reasoning.**
- The team has no strong stack preference; Python has the lowest friction for iterating on detection logic, which is where nearly all the work is.
- The Go ecosystem tools (naabu, subfinder, dnsx, httpx, nuclei) ship as static binaries. We get their speed with no Go code and no cgo.
- The Python-native tools we need later (garak, PyRIT, Prowler, MobSF, Checkov) are then first-class rather than subprocess bridges.
- One language means one dependency story, one test runner, one CI.

**Where this will hurt, and the plan.** Python is a poor fit for high-concurrency raw network work. Two components are expected to outgrow it:
- **The out-of-band callback server** — must be always-on, low-latency, multi-protocol. Write it in Go from the start (Phase 2). It shares no code with the scanners; it is a network service behind an HTTP API.
- **Our own TLS engine**, if we replace testssl.sh for speed. Go's standard TLS library makes this straightforward.

Both are isolated services behind interfaces, so this is a contained cost, not a rewrite.

**Trigger to revisit.** If a scanner's runtime is dominated by Python-side concurrency rather than network wait, port that scanner (not the platform) to Go behind the same contract.

**Reversal cost.** Medium, and per-component rather than global — which is the point of the contract.

---

## ADR-006 — A ground-truth corpus gates every scanner

**Decision.** No scanner is "done" until it passes a defined precision/recall gate against a corpus of targets whose correct answers we know in advance.

**Composition:** deliberately-vulnerable apps (Juice Shop, DVWA, VAmPI, badssl.com, our own broken fixtures), known-good assets we control, and frozen recorded responses replayed offline for determinism.

**Reasoning.** "It found something" is not evidence a scanner works. Without ground truth we cannot measure precision, cannot calibrate confidence (ADR-007), and cannot tell whether a change improved or regressed the engine. The corpus is also the seed of the labelled dataset that becomes our most valuable asset.

**Precision is weighted above recall.** A scanner that misses things is disappointing; a scanner that cries wolf is worthless and destroys the trust the whole product is built on.

**Consequences.** Every scanner ships with corpus entries. Adding a detection means adding a positive case *and* a negative case. CI runs the corpus on every change and fails on regression.

**Reversal cost.** Low, but abandoning it forfeits the product thesis.

---

## ADR-007 — Confidence is separate from severity, and calibrated

**Decision.** Every finding carries independent `severity`, `confidence` and `state`. Triage sorts by `severity_weight × confidence`.

**Reasoning.** Competitors ship "Critical: SQL Injection." We ship "Critical. Confidence 96%. Confirmed by independent re-test." A 95%-confidence High is more urgent than a 40%-confidence Critical, and no one else lets a user act on that.

**The hard requirement:** calibration. A stated 90% must be true 90% of the time, verified with reliability diagrams and Brier score per scanner. Uncalibrated numbers are worse than no numbers — they look precise and mislead.

**Granularity — a permanent constraint, not a milestone.** Calibration is fitted per **(scanner × detection_method)** bucket, never per `check_id`. A small customer base produces on the order of hundreds of labels a year across ~150 checks; per-check calibration would be undersampled indefinitely and would manufacture confident-looking noise. A bucket needs **≥ 30 labelled outcomes** before a fitted curve replaces its prior; below that the prior stands and `confidence_provisional` stays `true`. **For low-volume checks that may be permanent, and the UI must say so.** Platt-style scaling only in this regime — isotonic regression overfits below several hundred samples.

**Consequences.**
- Phase 1 confidence values are **provisional**, from hand-assigned priors, because we have no labels yet. This must be stated honestly in the UI.
- Every "false positive" mark, manual verification and fix-verification result feeds the labelled dataset. Collection is designed in from day one — findings must trace back to the exact detection method and evidence, or labels are useless.
- Detection-method *independence* must be tracked, or three variants of one method will masquerade as corroboration.

**Reversal cost.** High — it is in the schema, the ranking, and the UI.

---

## ADR-008 — Build the out-of-band callback server before Standard web scanning

**Decision.** The OOB server is Phase 2, sequenced before the Website Scanner's Standard mode.

**Reasoning.** Blind SSRF, blind SQLi, XXE and blind command injection cannot be proven any other way — and ADR-004 rules out the alternative. Without OOB, an entire class of findings is stuck at `suspected`, which undercuts the "we prove it" thesis on exactly the vulnerabilities that matter most.

**Requirements.** Self-hosted; separate domain from the main product; answers DNS, HTTP, HTTPS and SMTP (some bugs only exfiltrate over DNS); single-use scan-scoped expiring tokens; logs source IP, timestamp, protocol and full request as evidence.

**Bonus.** The identical service powers user-facing **Canary Tokens** (Phase 3) for almost no extra cost.

**[CORRECTED] Build vs adopt is not settled.** The original wording rejected "Interactsh-style" solutions on the grounds that customer data would transit infrastructure we do not control. That objection applies to ProjectDiscovery's **public** instance only. Interactsh is **MIT-licensed and explicitly self-hostable on your own domain**, supports all four protocols, and comes from the same team as naabu/subfinder/nuclei — already approved tools. Self-hosting it satisfies every requirement above without writing a Go service from scratch. **Evaluate fork-or-vendor before committing to a from-scratch build.**

**Operational detail that must be decided before Phase 2.** Wildcard TLS for `*.oob.ourdomain` requires the **DNS-01 ACME challenge** — HTTP-01 cannot issue wildcards — so the server needs programmatic DNS control and an authoritative nameserver. One wildcard certificate renewed roughly every 60 days is fine. **A certificate per token would hit Let's Encrypt rate limits immediately.** The design must be wildcard-based; this was unspecified.

**Reversal cost.** Medium. Using a *public* third-party instance remains unacceptable in production.

---

## ADR-009 — Postgres, a queue, and object storage for the platform *(Provisional)*

**Decision.** When Phase 6 arrives: Postgres for findings/assets/users/scans, a durable queue for scan jobs, object storage for evidence bodies and screenshots.

**Reasoning.** Scans are minutes-to-hours long and must never run in a request handler. Findings are relational and queried by many dimensions. Evidence is large binary data that does not belong in a database.

**Non-negotiable now, even before the platform exists:** every row carries `org_id` from the first migration, so multi-tenancy is not a retrofit.

**Left open:** specific queue, hosting, and web framework. See [07-open-questions.md](07-open-questions.md).

**Reversal cost.** Medium if changed before Phase 6, high after.

---

## ADR-010 — Import findings from the tools we cannot embed

**Decision.** Support importing output from Burp, Nessus, Nmap, Qualys, ZAP, Snyk, Semgrep and others; parse, deduplicate against our own findings, present one prioritised list.

**Formats:** Nessus `.nessus`, Nmap XML, Burp XML, SARIF (covers Semgrep, CodeQL and many others), CycloneDX and SPDX for SBOM, generic CSV/JSON.

**Reasoning.** This converts a licence limitation into an advantage.
- No legal risk — we read a file the customer already owns; we do not run their software.
- Zero licensing cost — the customer pays for their tools, not us.
- It makes us the **system of record**; everything converges in our platform.
- It is a wedge, not a compromise — over time customers notice our findings are proven and theirs are not, and the other tools become the replaceable ones.
- It kills a sales objection: "we already have Burp" becomes "great, bring it in."

**Consequence.** Imported findings must be visibly marked as unverified-by-us, and must not inflate our accuracy metrics.

**Reversal cost.** Low. Mostly parsing work.

---

## ADR-011 — "Compliance readiness", never "compliance"

**Decision.** The compliance tool is always described as *readiness*. We provide evidence; an auditor decides compliance. Never claim a customer is compliant, certified, or audit-passed.

**Reasoning.** Legal exposure. Only an accredited auditor can certify compliance, and claiming otherwise creates liability if a customer is later found non-compliant.

**Consequence.** This wording is binding on UI copy, marketing, reports and sales conversations — not just the docs.

**Reversal cost.** Not reversible.

---

## ADR-012 — Defer all platform, billing and account work to Phase 6

> **Superseded by [ADR-026](#adr-026--adopt-api-first-architecture-supersedes-adr-001-tool-first-and-adr-012-platform-deferral) (2026-10-02).** The v4 Phase 1 MVP includes accounts, ownership verification, billing and Free/Pro tiers, so they are no longer deferred to Phase 6. The text below is kept unchanged as the historical record.

**Decision.** No accounts, payments, dashboards, teams or tiers until the scanner shelf exists.

**Reasoning.** Direct consequence of ADR-001. These are well-understood, largely undifferentiated problems with mature off-the-shelf solutions; building them early consumes the time that should go into the only thing competitors cannot copy.

**Consequence.** Asset ownership verification (the legal prerequisite for Standard scans) is the one exception — it must exist before any Standard scan runs against a target we do not personally own. Until Phase 6, that is satisfied by an operator-maintained allowlist, not a self-serve flow.

**Reversal cost.** Low.

---

## ADR-013 — Accuracy gates are precision, recall **and** inconclusive rate

**Decision.** Gates are computed by the rules in [10-measurement.md](10-measurement.md). `confirmed` and `highly_likely` are the reported positives; `suspected` and `informational` are excluded and tracked separately; `inconclusive` is excluded from both numerator and denominator **and capped at 15%** on the frozen corpus tier.

**Reasoning.** The original plan set numeric precision/recall gates on output that is confidence-scored and five-stated, where binary precision/recall is undefined. Worse, excluding `inconclusive` without a cap creates an exploit: a scanner that returns `inconclusive` for everything scores perfect precision on the one thing it reports. The cap closes it.

**Also decided:** the corpus gains a **benchmark tier** — OWASP Benchmark and WAVSEP — because Juice Shop and DVWA carry only tens of planted vulnerabilities and no negative-case population. Precision computed on that sample is not statistically meaningful. WAVSEP alone contributes 816 path-traversal, 108 RFI, 66 reflected XSS, 80 error-based and 46 blind SQLi cases with known ground truth including negatives. Both are free and permissively licensed. Known caveat: synthetic benchmarks are overfittable and establish a floor, not real-world performance — which is why the live and known-good tiers remain.

**Reversal cost.** Low, but every published accuracy number before this decision is uncomparable to every number after it.

---

## ADR-014 — Descope the differentiation claims to what two people can actually own

**Decision.** Three of the five claimed differentiators are cut or reframed.

| Claim | Verdict | What we do instead |
|---|---|---|
| **Attack path + chokepoint analysis** — "the moat" | **Cut as a differentiator.** This is Wiz's and XM Cyber's core product, built by funded research teams. It also depends on an IAM/resource graph that does not exist until Cloud CSPM — a Phase 4 item secretly depending on Phase 5. | Ship **basic same-asset correlation** in Phase 4: group related findings into one story. Drop the chokepoint language entirely from internal and external framing. |
| **Reachability analysis** — the supply-chain differentiator | **Cut.** This is Endor Labs' entire company and a pillar of Semgrep Supply Chain. A credible single-language MVP is 3–6 months and would still be visibly worse. | Direct-dependency-only CVE matching via OSV.dev, using direct-vs-transitive as a crude but honest noise proxy. Say plainly that we do not do reachability. |
| **BOLA/BFLA multi-identity API testing** — "almost nobody does it properly" | **Keep the feature, kill the claim.** True around 2021–23. StackHawk shipped business-logic/multi-identity testing in Dec 2025; Escape and Akto already had it. | Build it — it is genuinely valuable. Position it as "with better evidence and honest confidence than DAST bolt-ons," not as novel. |

**What actually survives as ownable at this headcount:** rigorous evidence pairing, `inconclusive` as a first-class state, and free fix-verification. Narrower than "five things nobody does," and defensible.

**Reasoning.** Overclaiming against funded incumbents is how a small team wastes a year building the thing it is worst-placed to win. The tool-first strategy and the Scanner Contract remain sound; it is the *marketing* thesis that was inflated.

**Reversal cost.** Low — these are scope and framing decisions, revisitable if headcount changes.

---

## ADR-015 — Ownership verification exists from tool #1, not Phase 6

**Decision.** The mechanism specified in [09-ownership-verification.md](09-ownership-verification.md) is built before the first Standard-mode check runs against any target we do not personally own — including founder-run demo scans during customer validation.

**Reasoning.** ADR-012 deferred platform work to Phase 6 and named an "operator-maintained allowlist" as the interim gate, but never specified it. Meanwhile Phase 1's Email scanner includes Standard-mode checks (SPF chain resolution, open-relay testing) that run against real customer domains. The gate was therefore required from Phase 1 and specified nowhere.

**Also corrected:** every verification method previously listed (DNS TXT, file upload, meta tag, email) proves *domain* ownership. None work for **IP or CIDR targets**, which are a first-class target type for the Network Scanner. That gap is closed with RDAP/WHOIS registrant matching, reverse-then-forward DNS chains, and signed attestations — the last being mandatory for cloud-hosted ranges where the customer is not the registrant, alongside the cloud provider's own pentest policy.

**Consequences.** `core/authz.py` denies by default and requires an `authz_ref` on every Standard/Deep run. Authorisation records are immutable, retained 7 years, and expire after 90 days. The interim file is version-controlled, so git history is the audit log, and each row commits the actual proof alongside it.

**What it does not buy.** Verification proves control of a zone or web root — strong evidence of authority, not proof of legal ownership. A subtenant or a compromised account can pass. Reasonable effort is a defence, not immunity; the ToS must place the warranty of authority on the customer.

**Reversal cost.** Not reversible. It is the legal basis for the whole product.

---

## ADR-016 — Build our own TLS engine; keep testssl.sh as a cross-check

**Decision.** Tool 2 implements its own TLS inspection against Python's `ssl` and `socket`. `testssl.sh` is not wrapped at runtime. It is retained as an **independent cross-check in the corpus**: both run against the same targets, and a disagreement is a finding about us.

**This reverses the plan.** [05-phase-1-first-tools.md](05-phase-1-first-tools.md) says to start by shelling out to testssl.sh and parsing its JSON, replacing it when its runtime becomes the bottleneck. That was written before Phase 0 existed. Building Phase 0 changed two of its premises.

**Reasoning.**

- **Evidence is a by-product of observing, and a reconstruction of anything else.** Every finding owes a control-vs-test pair ([01-architecture.md](01-architecture.md)). When we make the handshake ourselves, the evidence *is* what we saw. Wrapping testssl.sh means parsing its verdicts and then working backwards to manufacture evidence for a conclusion someone else reached. That inverts the product thesis.
- **The hard part does not transfer.** testssl.sh's deepest value is its named-vulnerability probes, and most of those send deliberately malformed input. [ADR-004](#adr-004--no-exploitation-ever) already commits us to detecting those by version and configuration inference instead. We were never going to use them, which removes most of the "years of accumulated edge cases" advantage.
- **Cost per host shapes coverage.** 1–3 minutes per host sets a hard ceiling on how many hosts a scan can reach. Our own handshakes are seconds.
- **The integration is not free either.** GPLv2 means separate-process-only forever, enforced by the CI licence check. Its JSON schema broke between 3.0 and 3.2, so the version pin is load-bearing and every upgrade is a re-verification.

**What we keep from it.** testssl.sh becomes a second opinion rather than a dependency — the same role the second DNS resolver plays in the email scanner. Running both against the corpus and comparing is a real accuracy signal, and it is free of every constraint above because it runs at corpus time, not scan time, and never ships.

**Costs we accept.** Slower to a first working tool. We will rediscover edge cases testssl.sh already knows — SNI behaviour, chain construction, servers that hang rather than refuse. The cross-check harness is the mitigation: it tells us which ones we got wrong.

**Trigger to revisit.** If the cross-check shows us materially behind testssl.sh on the corpus after Tool 2 ships, and closing the gap looks longer than wrapping it would have been, wrap it for the checks we are losing and keep our own for the rest. That is a per-check decision, not an all-or-nothing one.

**Reversal cost.** Low. The Scanner Contract means a scanner can be replaced by a third-party wrapper without touching anything else, which is exactly the property ADR-002 was bought for.

**Amendment (D20, 2026-09-02) — the reserved per-check reversal, exercised.** "That is a per-check decision, not an all-or-nothing one" above is what this amendment invokes. RC4, 3DES and export-grade RSA/DH are compiled out of OpenSSL 3.5 — verified directly (`No cipher can be selected`), not assumed — so our own engine cannot probe for them at all, the same wall D11 hit trying to build a lab case for `tls-weak-cipher`. testssl.sh drives its own bundled OpenSSL and can.

`core/testssl.py` wraps testssl.sh **at runtime, for exactly four checks** (`tls-vuln-rc4`, `tls-vuln-sweet32`, `tls-vuln-freak`, `tls-vuln-logjam`), **in Standard mode only**. The 1-3 minute/host cost this ADR originally rejected as a blanket runtime dependency is accepted here, deliberately scoped: Light stays free and fast because none of these checks are `mode="light"`, and the cost lands only on the scans that already choose to spend minutes on a target.

Everything else about this ADR is unchanged and still the load-bearing decision:

- **The own-engine thesis holds for every other check.** Fourteen of eighteen TLS checks still make their own handshake; only these four reach for a second process, and only because our own engine is structurally incapable of the observation, not because wrapping was easier.
- **The corpus stays real, not reconstructed.** The four checks are proven against real recordings of public badssl.com weak endpoints (`corpus/generators/testssl.py`) rather than the local lab, which cannot serve a legacy cipher any more than our own client can negotiate one.
- **GPL isolation is unchanged.** `core/testssl.py` shells out to the pinned binary exactly as `corpus/crosscheck/testssl.py` already did; nothing from testssl.sh's source enters this tree, and the CI licence check still enforces subprocess-only.
- **Degrade, never crash.** Binary missing, subprocess error, timeout, or nothing recorded on replay all become `TestsslUnavailableError`, caught once in the scanner and reported as `inconclusive` — the same shape as `core.context.OobUnavailableError`.

`tools/registry.yaml`'s testssl.sh entry is updated accordingly: its purpose is no longer "NOT a runtime dependency" but "a runtime dependency for four Standard-mode checks; corpus cross-check for the rest."

---

## ADR-017 — Live verification is part of a tool's definition of done

**Decision.** A scanner is not done when it passes its corpus gate. It is done when it has **also** been run against real targets and every finding hand-verified. The live run is a gate condition, not a nicety, and its result is recorded in [14-progress-ledger.md](14-progress-ledger.md).

**Context.** Tools 1 and 2 both reached precision 1.000 on their corpora. Six real defects survived that:

| Defect | Why the corpus missed it |
|---|---|
| A fabricated SPF record quoted in a finding | The synthetic zone happened to match the hardcoded string |
| Rate limiter throttling the resolver, not the target | Replayed fixtures never wait |
| Thirteen findings for one host with no TLS service | No corpus case had a closed port *and* the full check set |
| Authorisation comparing raw strings, not assets | Every corpus target was typed one way |
| A row for one port authorising every port on the host | All four loopback rows were ours, so over-permission was invisible |
| A finding whose evidence did not contain its own claim | The case asserted the finding appeared, not what its evidence held |

**The pattern is not that the corpus was bad.** It is that a corpus written by the same person as the scanner encodes the same assumptions. Every case above passed because the test and the code agreed with each other. Real targets do not agree with anything — they are the only source of inputs nobody designed.

**Reasoning.**
- Precision measured against cases we authored is a measure of internal consistency. It is necessary and it is not sufficient.
- The corpus's job is **regression** — proving today's change did not break yesterday's behaviour. Discovering *new* failure modes is a different job and needs a different input.
- Live verification is cheap: a fifty-domain email sweep takes 33 seconds, and a handful of TLS targets take under a minute.

**Consequences.**
- Each tool's ledger entry records the live result — how many targets, how many findings, how many hand-verified.
- A live finding that turns out to be wrong becomes a corpus case, so the corpus grows in the direction reality points.
- **Verify with an independent method, not a second copy of your own assumption.** A near-miss: `openssl s_client -tls1` reported a handshake refused, which looked like a false positive in our TLS scanner. The refusal came from openssl's own security level, not the server. A verification tool carrying the same blind spot as the thing it verifies confirms nothing.

**Amended 2026-10-08: a check must be shown to fire before it ships.** Four advertised checks were found that cannot report a positive in production, yet every one passed its gate (ledger D28, D31, D37). A live run that finds nothing wrong on a healthy target does not show that a check can find anything at all. So the definition of done now includes, per check: **the check fired against a real positive**, a live target or a recording of one, hand-verified and cited in the PR. A corpus positive we wrote does not count. Where no real positive exists, the check ships marked UNDETERMINED in the [scanner catalogue](21-scanner-catalogue.md), with the reason stated, or it does not ship. Checks that were already shipped are not grandfathered as WORKING: they are counted as they stand in SPEC.md's standing figure.

**Amended 2026-10-08: every RFC a check cites must be current.** The same weight as the must-fire rule above. The DMARC checks were built, and fixed twice in one day, from RFC 7489 five months after RFC 9989 obsoleted it (ledger D44). Before a check ships or changes, each RFC it cites is confirmed against the RFC Editor's "Obsoleted by" field (`https://www.rfc-editor.org/info/rfcNNNN`, or the same data at `/rfc/rfcNNNN.json`). An obsoleted RFC means re-reading its successor and stating which one the check implements; it never means just swapping the URL. `make rfc-check` reads every citation in `scanners/` against that metadata. It needs the network, so it is not part of `make test`. Its first run found 5 obsoleted citations: RFC 7489 in `email`, and RFC 5246, 6125, 6962 and 7525 in `tls` (D44, D48).

**Amended 2026-10-09: legacy but deployed** (operator). An obsoleted RFC may stay cited when the check is about behaviour that is still deployed, such as a TLS 1.2 connection or today's CT logs. The successor is still read first, and cited too where it applies. The citation is then listed in `tools/rfc-exemptions.yaml`, with a written reason, the successor that was read, and where the "still deployed" claim was verified. `make rfc-check` reports such an RFC as exempt, not obsoleted. An exemption missing any of the three, or for an RFC nothing cites any more, fails `make test`, so it fails CI. Do not exempt an RFC to silence the check. First two exemptions: RFC 5246 (beside RFC 9846 for `tls-chain-incomplete`) and RFC 6962 (`tls-no-certificate-transparency`). Chrome's log policy accepts "either RFC 6962" or static-ct-api, and never mentions RFC 9162.

**Amended 2026-10-09: when standards disagree, read both, and take the worst case's severity.** RFC 9989 obsoletes RFC 7489, but receivers implementing either will be in service for some time.
- **Dual reading.** A check reads the current RFC first. Where the obsoleted one, still deployed, gives a different verdict, the finding states both readings and is capped at `suspected`. The verdict depends on the receiver, and we do not know which receiver will judge the mail. Where both agree, it is a claim like any other.
- **Severity is the worst case's.** For a receiver-dependent finding, severity is that of the worst outcome a receiver could produce. Severity is "how bad if true" and stays separate from confidence; the doubt is carried by the state. Lowering severity as well would discount the same uncertainty twice. For example, a misplaced `p=` is valid under RFC 9989, but an RFC 7489 receiver may discard the record, which is the same as no DMARC record. So it takes `dmarc-missing`'s severity, at `suspected`. A repeated tag follows the same rule.

**Costs we accept.** Live runs are non-deterministic and cannot gate CI. They stay a human step recorded in the ledger, not an automated one — which means they can be skipped under pressure, and the ledger is the only thing that would show it.

**Reversal cost.** Low, and inadvisable. Nothing depends on it structurally; dropping it just means the next six defects reach a user instead.

---

## ADR-018 — Findings carry a date, and say whether they were detected or derived

**Decision.** The Finding model gains two orthogonal additions. This reopens the frozen Scanner Contract deliberately, at two scanners rather than ten.

### 1. `materialises_at` — when a finding becomes true

```jsonc
"materialises_at": null,                  // true now. Every finding today.
"materialises_at": "2027-03-15",          // true from that date
"materialises_reason": "CA/Browser Forum SC-081v3 reduces the maximum certificate
                        lifetime to 100 days"
```

**Why a new axis rather than a new state.** The five states and their truth table are the most load-bearing thing we own; adding a sixth would touch every scanner and every corpus number. A dated finding is not a *different kind of belief* — we are just as certain a certificate is 200 days long as we are that it is expired. It is a belief about a different *time*. So `state` keeps its meaning, and `severity` becomes **how bad it will be when it lands**, which is coherent and needs no redefinition.

**It counts in the gate.** "Your certificate is 200 days and that stops being issuable in March 2027" is a claim that can be wrong, so it is measured like any other. Triage sorts by date alongside `severity × confidence`.

### 2. `derivation` — detected or derived

| | `detected` | `derived` |
|---|---|---|
| What it is | An observation of the target | A calculation from an observation plus a rule |
| Example | "This certificate expired on 2026-05-10" | "This 200-day certificate is not reissuable after 2027-03-15" |
| Confidence comes from | The confidence engine — priors and likelihood ratios | **Inherited from the finding it derives from** |
| Evidence is | The control-vs-test pair | The premise, plus the rule applied, plus the arithmetic shown |

**Why this matters more than it looks.** The confidence engine combines likelihood ratios — evidence that shifts a probability. A calendar date is not evidence, it is arithmetic, and forcing one through the other would mean inventing a fake likelihood ratio to clear the reporting threshold. That corrupts the one thing the engine exists to do.

**A derived finding is never more confident than its premise.** If we are 0.97 sure we read the certificate correctly, we are exactly 0.97 sure of everything we compute from it. `derived_from` names the premise so the chain is visible, and confidence is inherited rather than recalculated. That rule is what stops a "certainty" claim laundering an uncertain observation.

**Consequences.**
- `contracts/finding.schema.json` gains `materialises_at`, `materialises_reason`, `derivation`, `derived_from`. Additive; existing findings default to `null` / `detected`.
- `core/state.py` is unchanged. The truth table does not move.
- `core/confidence.py` gains an inheritance path for derived findings, distinct from `combine()`.
- [10-measurement.md](10-measurement.md) must report **detected vs derived claim counts separately**. Precision 1.000 across derived findings is a weaker statement than the same number across detected ones, because it partly measures arithmetic we wrote.
- The rules a derivation applies (deadlines, thresholds) are **curated data with a lifecycle**, not constants in code. See ADR-020.

**Reversal cost.** Moderate and falling. Two scanners and ~120 stored findings today. At ten scanners this becomes a real migration, which is exactly why it is being done now.

---

## ADR-019 — Scanners exchange assets through the run, never through each other

**Decision.** A `ScanRun` carries a shared **asset graph**. Scanners contribute discovered assets to it and read assets from it, through `ScanContext`. Scanners still never import one another.

**The problem.** "DNS enumeration produces the asset list every other tool scans" has been in the roadmap since v3 with no mechanism behind it. `related_assets` is one field on a finding, and the plan itself calls it "a cheap hedge, not a design". You cannot scan for exposed agent infrastructure without first discovering hosts, and Tool 3's entire value is being that input.

**The shape.**

```
ScanRun
  └── AssetGraph          discovered assets + how each was found
        ▲            ▼
   dns_enum      tls, web, ai_exposure      (contribute / consume, via ScanContext)
```

- **Provenance is mandatory.** Every asset records which scanner found it and from what evidence. An asset that appeared without provenance is a bug, not a discovery — and scanning something we cannot explain finding is exactly the authorisation problem the project exists to avoid.
- **Authorisation applies to discovered assets too, and is re-checked per asset.** Discovering `api.example.com` under an authorised wildcard does not authorise scanning something the enumeration merely *guessed*. `core/authz.py` remains the gate and is not bypassed by discovery.
- **Consuming is optional.** A scanner handed no graph scans its own target and behaves exactly as today. Nothing becomes order-dependent by accident.

**Why not let scanners call each other.** The no-import rule is what keeps a scanner replaceable, testable in isolation, and honest about its own inputs. Passing *data* through the run preserves all three; passing *control* would destroy them.

**Consequences.** `ScanRun` gains the graph. `ScanContext` gains read and contribute methods. The corpus harness needs a way to seed a graph for replay, so a consuming scanner is testable without running its producer.

**Reversal cost.** Low. A scanner that ignores the graph is unaffected.

---

## ADR-020 — Amends ADR-014: what we claim, now that the ground has moved

**Decision.** ADR-014 cut three differentiators as unownable at two people. That judgement stands for those three. This ADR adds four that did not exist or were not checkable when it was written, and names the discipline that keeps them honest.

**What ADR-014 cut, and still cuts:** attack-path/chokepoint analysis (Wiz, XM Cyber), reachability (Endor Labs), and the "almost nobody does BOLA" novelty claim. **Nothing in the 2026 research changes any of that.** Do not reopen them.

**What is added.**

| Claim | Why it is ownable |
|---|---|
| **Deprecation clock** — what breaks on a date, not just what is broken | It is a calendar applied to observations we already make, not a new engine. Competitors report the present. |
| **Post-quantum exposure** — is today's traffic harvestable and readable later | A concrete, checkable property of a handshake. Roughly half of domains fail it and almost no scanner reports it. |
| **Certificate lifetime readiness** — will renewal survive 47-day certificates | Dated, operational, and affects everyone. Reads a field we already parse. |
| **AI and agent exposure** — exposed MCP servers, agent panels, LLM endpoints | A genuinely new surface, passively detectable, and nobody has productised it. Fits ADR-004 without exception. |

**Why these pass the test ADR-014 set.** Each is *observation plus rule*, not a new research capability. None requires a graph we do not have or a corpus we cannot build. Each can be demonstrated in a single command against a real target — which is the honest test of whether a claim is real.

**The discipline that keeps them honest.**
- Every number quoted externally is verified against a primary source first. The v3.1 review found ~25 defects doing exactly that, and vendor blogs are not sources.
- A deprecation claim states its authority and its date. "We think this is bad" is not a clock.
- The clock's data is curated, versioned and reviewed ([ADR-018](#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived) derivation rules). **A rotted clock asserts wrong dates in our name, which is worse than not shipping one.**
- ADR-011 still holds: "compliance readiness", never "compliant".

**What has not changed.** The tool bundle is still not novel. Evidence, `inconclusive` and calibrated confidence remain the proof layer, and the four claims above are worth little without them — a date nobody believes is just another alert.

**Costs we accept.** Two of the four need foundation work before they can ship: post-quantum needs a toolchain we do not have, and AI exposure needs HTTP record/replay and the asset graph. Neither is a research problem; both are build cost, and both are recorded rather than assumed away.

**Correction, 2026-08-28 (0b.5).** The toolchain post-quantum needs is Python **3.15** (`ssl.SSLContext.set_groups`/`get_groups`, `SSLSocket.group()`), not 3.13 as this ADR and the roadmap originally implied — verified directly by checking the `ssl` module across 3.12/3.13/3.14/3.15rc1. Python 3.13 was still taken (D16), but it does not unblock this claim. Same category as D13: a number that reached a decision document without being verified against the primary source, here CPython's own `ssl` module rather than a vendor blog.

**Reversal cost.** Low. These are scope and framing decisions, as ADR-014's were.

---

## ADR-021 — The IoT & Device Security Scanner is its own tool, not a check family

**Decision.** IoT gets a **distinct tool with its own gate, its own corpus and its own plan document** ([15-iot-scanner.md](15-iot-scanner.md)), reusing `core/` like every other scanner. It is positioned as a headline capability rather than an extension of the network scanner.

**Why a separate tool rather than checks bolted onto Network.**

- **It scans a different kind of thing.** Every tool so far takes a domain or a URL. This takes a *network* — a CIDR, a VLAN, an address range — and its primary output is an **asset inventory**, not a finding list. That is a different deliverable for a different buyer.
- **It is the only tool that runs inside the perimeter.** Different authorisation story, different risk profile, different rate limits.
- **Its accuracy problem is genuinely different.** Everything else measures something we can observe directly. IoT CVE matching is inference from an unreliable identifier, and it needs its own measurement discipline (below).
- **A differentiator has to be nameable.** "Our network scanner also does some IoT checks" is not a pitch. A tool with a name, a gate and a demo is.

**The claim.** Not "we scan IoT" — plenty of tools say that. The claim is:

> **The scanner you can safely point at fragile devices, that tells you which vulnerabilities it actually confirmed and says "I do not know" when it cannot tell.**

Two seams that exist because of how the market is built:

1. **Existing tools are either passive or aggressive.** Passive OT monitoring needs a network tap and enterprise money. Active scanners are built for servers and knock devices over. A *deliberately gentle active* scanner is an unoccupied position, and our no-exploitation rule ([ADR-004](#adr-004--no-exploitation-ever)) becomes a feature rather than a limitation — we can honestly say we will not brute-force a credential or change device state.
2. **IoT CVE matching is the noisiest output in security scanning.** Vendor strings are inconsistent, NVD's CPE coverage for consumer devices is poor, firmware versions are often absent from the dictionary, and the same model ships different regional builds. The industry norm is to print forty criticals from a banner match. **Our existing rules — version-only caps at `suspected`, `inconclusive` when we cannot tell, independence classes before `confirmed` — are already the right answer, and they are worth most exactly where the noise is worst.**

**A refinement to the version-strings-lie rule, with its reasoning.** [06-guidelines.md](06-guidelines.md) caps version-only findings at `suspected`, confidence ≤ 0.6, because distributions backport security patches without bumping versions. **IoT firmware rarely works that way** — vendors ship a new build or nothing. So a firmware version is a *stronger* signal than a distro package version, and the cap for `firmware_version` may justifiably be higher. This is a documented exception with a stated cause, not a loophole; the corpus must demonstrate it before the cap moves.

**The hard constraint.** Devices are fragile in a way servers are not. A request rate a web server ignores can knock over a sensor or a PLC. **This is the most dangerous scanning we will ever do**, and the gentleness is not a default to be tuned away — see [06-guidelines.md](06-guidelines.md).

**Dependencies, stated rather than assumed.** Protocol clients in `core/`, the generic record/replay layer (0b.3), and — for the vulnerability half — port discovery from the Network Scanner. The **exposure half needs none of the latter**: with an authorised range it can probe the dozen known device ports directly, which is why it is split in two.

**Reversal cost.** Low. It is a scanner like any other; the Scanner Contract means it can be dropped without touching anything else.

---

## ADR-022 — Prove, connect, close: aggressive proof, never touching the target

**Decision.** The product's differentiator on the mitigation side is a three-part loop — **prove** a finding, **connect** related findings into one story, **close** a finding with a re-test — built entirely within [ADR-004](#adr-004--no-exploitation-ever). Nothing here runs code on a target, changes state, or reads real data. It makes the *target* demonstrate the problem instead of us claiming it.

**Why this and not exploitation.** "Offensive capability" for a scanner usually means running exploits. That crosses ADR-004, which is not reversible — it is the product's legal identity. The ownable move is not to *break in* but to make the proof undeniable without breaking in. That is a sharper differentiator anyway: anyone can print a critical; making the customer's own infrastructure prove the critical is what a severity score cannot do.

### 1. Prove — the validation engine, promoted to flagship

Already in the architecture as a component. It is the flagship, and the docs should say so.

- A detection produces a candidate.
- Validation re-tests with an **independent method** — a different payload family, a different observable channel.
- Blind and asynchronous bugs prove via **out-of-band callback**: the target is made to request a unique URL only we control. If our server is hit, the bug is proven with certainty and nothing was touched.
- Only a passed validation can lift a finding to `confirmed`.

The pitch sentence: *"We didn't guess. We made your server phone us."* No competitor's confidence number says that.

### 2. Connect — same-run correlation, not the attack-path moat

[ADR-014](#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own) cut attack-path analysis, and that stays cut — it is Wiz's product and needs a graph we will not have. **This is the nearer, ownable slice:** within one run, over the asset graph ([ADR-019](#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other)), group findings that compose into a single attack.

An exposed MQTT broker + a device with a known RCE + a flat network is not three medium findings. It is **one critical story**, and reported as one. The correlation is a set of hand-written **composition rules** ("exposure + weak-auth on the same asset raises the severity of both"), not a machine-learned graph. Rules are auditable, which the moat version is not, and a two-person team can own a rule set.

**A correlation is itself a `derived` finding** ([ADR-018](#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived)): its confidence is inherited from the weakest finding it chains, never invented. A story is only as believable as its least certain link, and saying so is the honest version of "critical".

### 3. Close — fix verification as a first-class capability

Named as a differentiator since v2, **never designed**. This ADR makes it real.

- Every finding records the **exact test that proved it** — the same replayable evidence the finding already carries.
- Re-running that test is a first-class operation: `scan verify <finding-id>`. It re-executes only that check against the same target and compares.
- The result transitions the finding's `status`: `open → closed` with fresh evidence, or `open` still, with the failed re-test recorded.
- **Always free**, forever. Opening problems is what everyone does; closing them with proof is the retention hook.

This needs a **finding lifecycle** the contract half-has: `status`, `status_history` and `first_seen`/`last_seen_scan_id` already exist; what is missing is the operation that drives them and a store that persists a finding between scans. Both are Phase 0b foundation work (0b.8).

### 4. Prioritise — the by-product that makes a report actionable

Once findings connect, "fix these first" falls out. A finding that is a link in three attack stories outranks an isolated one of the same severity. **`severity × confidence` orders a list; composition orders a plan.** This is not new engineering — it is a sort over the correlation output — and it is the single thing that turns a 200-item report into a Monday morning.

**Consequences.**
- The validation engine and OOB server (Phase 2a) are reframed as the flagship, not a component.
- `core/` gains a **correlation pass** that runs after all scanners in a run, reads the asset graph and findings, and emits `derived` correlation findings. It imports no scanner.
- A **finding store** and a `scan verify` operation (0b.8).
- Composition rules are **curated data with a lifecycle**, like the deprecation calendar — versioned, sourced, reviewed.
- [10-measurement.md](10-measurement.md): a correlation finding is scored as `derived`, and its precision is reported separately.

**Costs we accept.** Correlation can over-tell a story — three findings that *look* like a chain but are not. The mitigation is the same as everywhere: a composition rule states its premise, the confidence inherits from the weakest link, and a chain that cannot be justified is not drawn. Under-telling (missing a real chain) is preferred to over-telling, consistent with precision-over-recall.

**Reversal cost.** Low for connect and prioritise (scope/framing). Moderate for close — the finding store is real infrastructure, which is why it is foundation work done before the tools that will lean on it.

---

## ADR-023 — Passive is ordinary negotiation; only malformed input is active

**Decision.** A check is **passive** if it does what an ordinary client does — completes a connection and reads what the server presents. A check is **active** only if it sends **malformed or exploit-adjacent input**. Completing a handshake at an obsolete protocol version, or with a legacy cipher list, is **passive**. This reclassifies `tls-protocol-obsolete`, `tls-weak-cipher` and `tls-no-forward-secrecy` from active to passive, which makes **every TLS check passive** — so TLS needs no authorisation in any mode, the same as email.

**This reverses the 0b.6 first cut.** [Phase 0b.6](14-progress-ledger.md) drew the line at "deliberately abnormal input": offering `core.tls.PERMISSIVE_CIPHERS` (`ALL:@SECLEVEL=0`) or pinning a ClientHello to TLS 1.0 to see what a server accepts was called active. That conflated *abnormal* with *harmful*.

**Reasoning.**

- **A completed handshake changes nothing.** Offering an old protocol or a weak cipher in a ClientHello is a normal negotiation the server freely accepts or refuses. No state changes, nothing is exploited. That is categorically different from the malformed input [ADR-004](#adr-004--no-exploitation-ever) forbids — a Heartbleed heartbeat, a ROBOT padding oracle — which stays active and which we do not send at all.
- **The whole market treats it as free and unauthenticated.** SSL Labs, SSL.org, Mozilla Observatory and testssl.sh all enumerate protocols and ciphers against any host, no ownership check. Measured directly: SSL Labs' public API enumerated TLS 1.0/1.1/1.2 and 35 cipher suites on `<operator ERP host>` with no authorisation. Gating what everyone else gives away left our free Light tier looking thinner than a generic free tool — the gap that prompted this ADR.
- **It does not weaken the gate.** Deny-by-default is intact; `passive: bool` still has no default, so an undeclared check is still active. What changed is one line of judgement about three checks, not the mechanism. The active path stays enforced and tested (synthetic checks in `test_authz_passivity.py`); its first live consumer is the Website Scanner's payload-sending checks.

**Consequences.** All 14 TLS checks are `passive=True`. TLS Standard now runs with no authorisation record, like email Standard. `core/authz.py` is unchanged. Documented everywhere the split was stated (00-context, SPEC, runbook, this ADR), because it is an authorisation-gate behaviour change and those get recorded in every place an operator might look.

**Reversal cost.** Low. Flipping a `passive` flag back is a one-line change per check; the gate machinery never moved.

---

## ADR-024 — Competitive coverage parity is part of a tool's definition of done

**Decision.** Before a tool ships — and retroactively for the two already shipped — it is benchmarked against a named set of **reference tools**, and must **meet or beat the checks they surface, or record an explicit reason not to.** This extends [ADR-017](#adr-017--live-verification-is-part-of-a-tools-definition-of-done): "verify against reality" gains "and against the incumbents."

**Why.** Two shipped tools passed their gates at precision 1.000 and were then found, by a real head-to-head, to surface *less* than a generic free tool (SSL.org showed a chain, protocol versions, CT and key strength for TLS where our free tier showed an expired cert). Accuracy on the checks we chose says nothing about whether we chose enough checks. A gate measures how well we do what we decided to do; it cannot tell us the incumbents do more. Only looking can.

**The rule this sets.**

- **Coverage is table stakes; proof is the wedge.** We do not need to out-field-count SSL Labs. We need enough coverage that a buyer takes us seriously, and *then* evidence, calibrated confidence, honest `inconclusive` and unification is what wins. Over-correcting into "match every field the incumbents show" would make us a worse clone; the target is *par on the obvious, ahead on the wedge*.
- **A declined check is recorded, not silently missing.** Named-vulnerability probes that send malformed input (Heartbleed, ROBOT active oracles) are out by [ADR-004](#adr-004--no-exploitation-ever) — that is a principled decline with a written reason, not a coverage gap. Many of those same vulnerabilities are detectable by *inference* from accepted protocols and ciphers (POODLE = SSLv3, BEAST = TLS 1.0+CBC, FREAK = export ciphers), and inference is in scope.

**The method boundary — the licence line, stated so it is not crossed later.** We may read a competitor's **output** and its **published methodology** to build a coverage checklist — "what does a credible TLS tool surface?" is a factual question, and the authoritative answers are public (SSL Labs' rating guide, Mozilla Observatory's open source, the RFCs, testssl.sh which we already cross-check). We may **never seed our checks, rules, or fingerprint data from a proprietary tool's output.** That is the Wappalyzer-fingerprint-data trap ([ADR-003](#adr-003--permissive-open-source-or-we-build-it-ourselves)) one level up: parity is built from primary sources, not by cloning an incumbent's logic out of its results. Automated scraping of competitor services is for bounded manual research only, never a standing runtime dependency.

**Reference sets (initial).** TLS: SSL Labs, SSL.org, Mozilla Observatory. Email: MXToolbox. Extended per tool as they are built.

**Reversal cost.** Low — it is a definition-of-done item, not infrastructure.

---

## ADR-025 — Authorized exploitation, Deep tier only, opt-in per scanner

**Decision.** [ADR-004](#adr-004--no-exploitation-ever)'s default stands as the product's identity: **no exploitation in Light or Standard, ever.** This ADR defines the single narrow exception. A **Deep/Validated** scan *may* perform controlled exploitation to confirm a finding, **only** when **all** of the following hold:

1. The customer has signed the **explicit authorization agreement** for that asset — the Q5 legal artifact ([07-open-questions.md](07-open-questions.md)), which does not yet exist. No agreement, no exploitation, full stop.
2. The specific scanner **declares itself exploitation-capable** — a per-scanner opt-in, the same shape as the per-check `passive` declaration ([ADR-023](#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active)). Deny-by-default: a scanner that says nothing never exploits.
3. The finding **genuinely cannot be confirmed by inference or by out-of-band proof** ([ADR-022](#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target)). Exploitation is the last resort, never the first reach. If OOB can prove it, OOB proves it.

**Hard exclusions — these never exploit, even in Deep, even with an agreement:**

- **The IoT & Device Security Scanner** ([ADR-021](#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family)). Its entire claim is that it is safe to point at fragile devices; a device does not care that you are authorized, and exploitation can physically brick it. This exclusion is stop-the-line.
- **Anything that changes persistent state or extracts real data.** We may prove a SQL injection executes; we never dump the table. We may prove a write is possible; we never leave the write in place. The line ADR-004 draws around *data* and *state* does not move — Deep exploitation proves reachability, never consequence.

**Why this is an amendment and not a reversal.**

- **Real authorized testing includes it.** Deep/Validated already requires a signed authorization agreement precisely because it does more than Standard. Controlled exploitation of an asset the customer owns, with written consent, is what a pentest engagement is — legally practiced, and distinct from touching a system you were not invited to.
- **Some findings are unreachable any other way.** A handful of vulnerability classes cannot be *confirmed* without triggering them. For those, ADR-004's inference gives `highly_likely`; ADR-025 lets a consenting Deep customer reach `confirmed`. That is the whole value of the Deep tier — proof, not stronger suspicion.
- **The default and the moat survive.** "Safe by construction" remains true of the free and paid-standard product, which is where the market comparison happens and where the sales material must stay anchored. Exploitation is an opt-in escalation a customer asks for, never the headline.

**Caveats recorded so they are not lost.**

- **Gated behind three things that do not exist yet:** Deep mode, the OOB server (Phase 2a), and the Q5 authorization agreement (open 🔴 legal). This ADR is a *recorded direction*, not buildable now, and must not be built until those land. It changes nothing in the two shipped scanners.
- **Liability is real for a two-person team.** One exploitation defect against a customer's production can end the company. That is why it is Deep-only, opt-in, last-resort, and behind a signed agreement — the containment is the point, not bureaucracy.
- **Sales discipline.** The marketing stays on *safe-by-default*; exploitation is described, if at all, as a consenting Deep-tier escalation. The moment a deck implies the product exploits by default, [ADR-004](#adr-004--no-exploitation-ever)'s selling point is lost.

**Reversal cost.** Low today, because nothing is built — it is a policy plus a future per-scanner flag. It rises as scanners gain exploitation capability, which is the argument for keeping the flag opt-in and the exclusions hard from the first line of code.

---

## ADR-026 — Adopt API-first architecture (supersedes ADR-001 tool-first and ADR-012 platform deferral)

**Decision.** The v4 plan ([18-v4-plan.md](18-v4-plan.md)) replaces the tool-first build order of [ADR-001](#adr-001--build-tools-first-platform-second). `api/` and `web/` are now built from Phase 1 of the v4 migration, not deferred to Phase 6. It also supersedes [ADR-012](#adr-012--defer-all-platform-billing-and-account-work-to-phase-6): the v4 Phase 1 MVP includes accounts, ownership verification, billing and Free/Pro tiers ([19-v4-roadmap.md](19-v4-roadmap.md)), so none of them waits for Phase 6. Every capability is exposed through `api/` first, and `web/` is a thin client of it that holds no logic of its own. The schedule is in [19-v4-roadmap.md](19-v4-roadmap.md) and the steps are in [20-migration-runbook.md](20-migration-runbook.md).

**What carries forward unchanged.** ADR-001 named the Scanner Contract ([ADR-002](#adr-002--freeze-the-scanner-contract-before-writing-tool-1)) as what lets the platform be built at any time without touching scanners, and this ADR relies on that. The contract stays frozen. The validated `core/` services and the shipped scanners are extended, not rebuilt. Every accuracy gate, licence rule, the no-exploitation rule and the ownership rule still apply.

**Reversal cost.** Low while `api/` and `web/` are empty. It rises with every endpoint and screen built on them, and sharply once accounts and billing hold customer data.

---

## ADR-027 — A fixture may stand in for a real service only on recorded evidence

**Status.** Decided (operator, 2026-10-08). Binds every scanner and every corpus generator, starting with Tool 4b.

**Context.** The corpus-fidelity audit of 2026-10-08 (see [14-progress-ledger.md](14-progress-ledger.md), "Corpus-fidelity audit") found two shipped `domscout` checks broken in production. Both passed their gate.
- `domain-expiring` has never read an expiry date live, for any TLD (D28). The generator wrote rdap.org as answering `200` with the record. The real service answers `302` to the registry.
- The S3 and Heroku takeover fingerprints can never fire (D31). The generator wrote abandoned targets as `NXDOMAIN`. The real services resolve every name, real or not.

In both cases the parser, the scope rule and the gate each did their job. The gate measured the scanner against a version of the service that does not exist. A generator that fabricates a third party's behaviour can make a scanner pass its gate while it is broken in production. [ADR-017](#adr-017--live-verification-is-part-of-a-tools-definition-of-done) already requires live verification. This ADR closes the gap that let a corpus disagree with the live world without anyone noticing.

**Decision.**

1. **A generator may hand-write a third party's response only if a cited recording of the real service backs it.**
   - A third party is any service the scanner talks to that we did not build: registries and RDAP servers, CT logs, hosting providers' DNS and HTTP, public resolvers, external APIs.
   - The citation is a committed recording, or a ledger entry with date, URL and what was observed. It must show the real status code, the redirect hops, the header set, the body shape, and the failure modes the scanner must handle, for example a bootstrap `302`, wildcard DNS, or a `502`.
   - The hand-written response must reproduce that shape. A simplified shape is allowed only if the simplification is stated and the omitted parts are covered by a live case.
2. **Lab targets we build are real software, and that is allowed.** Examples are nginx, Django and the OpenSSL lab: the defect is ours, the behaviour is the product's. A lab setting that imitates a product we do not run, such as an `X-Powered-By: PHP/…` header with no PHP behind it, must cite a real observation of that product's format.
3. **Generated HTTP responses carry realistic header sets, and a contract test rejects any committed HTTP fixture with no headers at all.** The reason, from the audit: *a fake with no headers can never contain a redirect. This is what hid D28.* Every `domscout` HTTP fixture recorded `headers: {}`, so no fixture could carry a `Location`, and the redirect path was never exercised. An empty header set is not a simplification. It removes a whole class of real behaviour.

**Consequences.**
- **Existing fixtures that break this ADR today:**
  - all 9 `domscout` cases: the rdap.org shape, the S3/Heroku `NXDOMAIN`, the crt.sh shape (unverified), and empty headers throughout;
  - the `email` zones, which are authored targets served by an in-memory fake rather than real DNS software. D7, a CoreDNS lab, is the route to clause 2.
- **The contract test (clause 3) lands with the `domscout` re-record (D28/D31).** Landing it earlier would fail on those fixtures, and an allowlist of known violators would invite the next one.
- **New scanners (Tool 4b onward):** a generator review asks clause 1's question for each external service before the corpus is frozen.
- **The method that passed the audit is the standard:** real recorded traffic, live hand-verified hosts, and an external cross-check. Only `web` (Tool 4a) was built that way, and only `web` came out clean.

**Reversal cost.** Low. It is a review rule and one contract test, and dropping either changes no shipped behaviour. The cost of not having it is a gate number that is false in production, and that has already happened twice.

---

## ADR-028 — Core redacts secrets by value at every point where text is stored, and never redacts public key material

**Status.** Accepted 2026-10-09 (operator). Closes ledger D21. Implemented on `fix/d21-core-redaction`, with an independent review before merge.

**Context.** Hard constraint 5 says never store customer secrets, and redact at capture time, not at display time. Until this ADR, `core/` fell short of that in four ways, and every scanner inherited them:
- `redact_headers` matched header **names** only. A secret in a non-sensitive header's **value** (`Server: nginx AKIA…`) was stored.
- The `private_key` pattern matched only the `-----BEGIN … PRIVATE KEY-----` line, so the key body was stored, in evidence and in recorded fixtures.
- Finding text was never redacted: titles, descriptions, impact, remediation and locations.
- Error messages were never redacted: `ScanError`, exception text, CLI output.

`web` worked around all four on the scanner side (Tool 4a, three leak-fix rounds and a 153-case attack harness), which is the wrong place: every scanner has to remember, and `domscout` did not.

**Decision.**
1. **One redactor, in core** (`core/redaction.py`). Scanners do not redact. It covers:
   - the token patterns: AWS access key, GitHub token, bearer token, Slack token, Google API key;
   - **whole PEM private-key blocks**, whatever the label (`RSA`, `EC`, `DSA`, `ENCRYPTED`, `OPENSSH`, PGP `PRIVATE KEY BLOCK`) and whatever separates the lines: newlines, CRLF, escaped `\n`/`\r\n`, `<br>`, `&#10;`/`&#xa;`, JSON-escaped `\/`. A block with no END line is cut to the end of the text. An END line whose BEGIN was lost is taken with the key lines above it, and so is a run of bare 40–100-column base64 lines whose BEGIN and END were both truncated away.
2. **Secrets, not public key material.** This is the carve-out, and it is load-bearing.
   - The PEM matcher acts only on labels containing `PRIVATE KEY`. `CERTIFICATE`, `PUBLIC KEY` and every other public label are kept intact, including their base64 bodies.
   - The bare-base64 heuristic never touches a run inside or adjoining a public PEM block.
   - The heuristic is applied **only to HTTP bodies, header values and free text**. It is never applied to DNS records, certificate data or any other public key material: a DKIM `p=` value is a public key, and `dkim-weak-key` measures key size from it.
   - **DNS record text and TLS certificate strings get the token patterns and private-key blocks only.** Deliberately public tokens, such as `google-site-verification=…`, survive.
3. **Checks evaluate raw data; redaction happens at storage.** A scanner reads the live response, DNS answer or certificate unredacted, in memory, for the duration of one check. What is redacted is what is *kept*: evidence, findings, fixtures, the store, errors, logs. No check may decide anything from redacted text.
4. **Redact first, then truncate, everywhere in core.** Truncating text is possible only through functions that redact first and cut so that no marker is split. The cut text is then redacted again, because a cut can create a new word boundary. Cap-before-redact, the Tool 4a bug, cannot be written against core.
5. **Every storage point goes through it:**
   - HTTP captures (request URL, header names and values, bodies) in evidence and in recorded fixtures, with replayed fixtures re-redacted;
   - evidence objects however they are built;
   - `Finding` text fields;
   - `ScanError` messages;
   - CLI output, the progress stream, and uncaught exception text.
6. **One way in.** `Finding` redacts in a model validator, and every model validates on assignment. So `Finding.create`, direct construction, attribute assignment, `model_validate`/`model_validate_json` deserialisation and **loading from the store** all redact. Evidence objects inside a finding are re-validated, so one mutated after it was built is redacted too. `model_construct`, which skips validation, is blocked on every core model, and `model_copy` and the deprecated `copy` re-validate. The store re-validates at write as well, and rewrites at rest any row that loading changed. So a store written before this ADR becomes safe on the way out *and* on disk. If the rewritten row's new id already belongs to a stored row, that row is newer and keeps its status and history; the legacy row is only deleted. The first time a store is opened, every row is loaded this way before anything else touches it (marked by `PRAGMA user_version`, set only once every row has loaded). A store that cannot be written is opened read-only and copied into memory, and the same sweep runs on the copy: redacted in memory, nothing written back. Redaction can be re-run, so this repeats safely on every open, so a re-scan that writes first cannot leave a legacy secret on disk or reopen a legacy finding's status.
7. **Re-running redaction is safe, and markers are inert.**
   - Running the redactor twice gives the same result as once.
   - A whole private-key block is replaced by `[redacted:private_key]`, which is never read as the start of anything.
   - The legacy marker `[redacted]:private_key`, which old core left in place of a BEGIN line while keeping the body, *is* read as a block start, so captures from before this ADR are cut correctly too.
8. **Over-redaction is the accepted price.** Genuine base64 columns in a web page become a marker in stored evidence. Verdicts never depend on stored text (clause 3), so corpus numbers do not move.

**Consequences.**
- `web`'s scanner-side workaround is removed only if the 153-case harness, re-run against core directly and then against `web` end-to-end, live and on replay, still reports 0 leaks without it. If any case fails, the workaround stays.
- A finding whose *location* contained a secret gets a new deterministic id, because the id is computed from the redacted location. Losing history for such a finding is correct: we must not key on a secret.
- Every scanner's corpus numbers must be unchanged. A change means a check was reading stored text, which clause 3 forbids, and is a defect.
- **Replay can see less than live, for every content check.** A fixture is stored text, so it is redacted, and an unterminated private key is cut to the end of the text there too. **Anything a check reads that comes after such a key** is present live and absent on replay: a traceback (`web-error-disclosure`), an `http:` script (`web-mixed-content`), a script tag (`web-sri-missing`), a version string. The secret itself is still reported on replay. Accepted: a key has no safe partial boundary, and hard constraint 5 outranks replay fidelity for a page that publishes an unterminated private key. Found by the D21 test `test_unterminated_br_key_on_the_404_page_is_never_stored`, and widened by the independent review.
- **A heuristic cut is not a verdict.** A whole private-key block, or an orphan END line, is counted as `private_key`. A bare base64 run with no armour is counted as `possible_key_material`, which no check treats as an exposed secret. A MIME-wrapped image or a checksum list is kept out of storage, never reported as a key.
- **A legacy stored finding whose location held a secret is re-keyed on first load.** Its id is computed from the redacted location, the old row is deleted, and SQLite's `secure_delete` overwrites it. References to the old id, such as `scan verify <old id>`, then find nothing.
- **The redactor protects text core stores, not text a scanner has already cut.** A scanner that slices raw text itself (`text[:200]`) before handing it to a finding can split a key below the size the heuristics recognise. Scanners must use `core.redaction.cap_text` or `cap_prefix` to shorten text, never a raw slice. That is a review rule, checked in `how-to-add-a-scanner`.
- **Token patterns need word boundaries.** A token glued inside a longer word (`xxxxAKIA…`) is not recognised, as before ADR-028. A recall limit, not a regression.

**Reversal cost.** High, and inadvisable: reverting re-opens hard constraint 5 for every scanner.

## ADR-029 — Redaction receipts: what was removed is recorded, never what it was; a receipt on public content is a finding

**Status.** Accepted 2026-10-09 (operator). Proposed alongside ADR-028. The field name, its placement and the emitter were decided by the operator on 2026-10-09.

**Context.** ADR-028 removes every secret before storage, so a customer cannot see what was removed or where. The evidence's `redactions` list (frozen contract, a list of kind names such as `"set-cookie"`) says which kinds were removed but not how many or from which part. Also, `web` is the only scanner that reports a secret it found in public content (`web-secret-in-response`). `email` and `domscout` capture public content too (DNS records, MTA-STS policies, the pages of a domain's subdomains) and redact secrets in it without saying so.

**Decision.**
1. **A new, optional field on every evidence item: `redaction_receipts: [{kind, count, where}]`.** For example, `{"kind": "aws_access_key_id", "count": 1, "where": "test.response.body"}`. It is additive: the existing `redactions` list is unchanged, and old evidence stays valid.
   - `kind` is the redactor's name for what it removed.
   - `count` is how many were removed there.
   - `where` is a field path from a fixed vocabulary: `<side>.<part>.<field>` for HTTP (`test.response.body`, `control.request.url`), `<side>.<part>` for DNS and TLS exchanges (`test.answer`), or a top-level evidence field (`analysis`, `data`).
2. **A receipt never records the value, a prefix, a suffix, the length or a hash.** A hash of a low-entropy token can be brute-forced, and a length narrows the guess. The schema enforces the three fields with `additionalProperties: false`, and `where` is never built from data: no header name, no URL, no record text.
3. **A `Finding` rolls up its evidence's receipts** in its own `redaction_receipts`, with `where` prefixed by the evidence index (`evidence.0.test.response.body`). The rollup is computed by the model from the evidence and is never taken from input, so it cannot disagree with the evidence.
4. **Receipts are made at capture and survive replay.** `core/http.py` records them in the capture and in the fixture, and replays them from it. A fixture recorded before this ADR has no receipts, and none are invented for it. Re-redacting stored text finds nothing new, because redaction is idempotent, so re-validation never double counts.
5. **A receipt on publicly served content is a finding.**
   - **Publicly served content** means a response's headers or body, or a DNS answer, served by the target: the target host or a name under the target domain. Our own requests are not public content, and neither are a third party's service hosts (crt.sh, rdap.org) or another zone's records.
   - **The kinds that count are credentials:** `aws_access_key_id`, `github_token`, `slack_token`, `bearer_token` and `private_key`. These are the same as `web`'s. `google_api_key` is excluded, because browser keys are public by design. So are the sensitive-header kinds (a `Set-Cookie` header is normal) and `possible_key_material`, a heuristic cut that is not a verdict (ADR-028).
   - **The emitter is a core helper** (`core/exposure.py`). A scanner calls it with its findings, and it returns one `secret-exposed` finding per exposed resource, under the scanner's own name, severity `high`. Its claim is "text matching the credential pattern(s) K was served at R. It was removed when captured and is not stored." Its state is computed by `core/state.py`, like every other finding's.
   - **`web` does not call it.** `web-secret-in-response` already reports the same thing, so calling it would report every exposure twice.
6. **A contract test makes forgetting impossible.** If any public capture in a scan (its exposure log, or any evidence item) holds a credential on content the target served, the result must also hold a finding that reports that resource: either `secret-exposed` or `web-secret-in-response`. The test runs every registered scanner over its corpus, so a future scanner is covered without being listed. A fake scanner that captures a secret and does not call the helper must fail it.

**Consequences.**
- `email` and `domscout` gain secret detection without storing anything. **Their `secret-exposed` checks ship UNDETERMINED** under ADR-017 until each fires on a real positive. Each has a synthetic positive and negative corpus case.
- **Every public capture the scan made is checked, not only cited evidence** (review of the first implementation). `ScanContext` wires an in-memory `ExposureLog` into its HTTP and DNS clients, so the scan sees every response and every fresh DNS answer, and the helper and the contract read it. Without it, a secret in the TXT record of an otherwise clean zone went unreported, because no finding cited that record. A capture recorded before this ADR has no receipts, so the log falls back to its `redactions` kinds: a kind is enough to report, and no count is invented. The log lives for one scan and is never stored.
- **`scan verify` cannot close a `secret-exposed` finding yet.** The helper reports an exposure; it does not run a check that can come back `clear`. So verify says "could not verify", which is the honest outcome.
- `email`, `domscout` and `web` bump `scanner_version`, because their evidence now carries receipts. `tls` evidence carries the empty field and no receipt in any corpus case, so its version is unchanged.

**Reversal cost.** Low for the finding: drop the helper calls. The field is additive, so removing it is a contract migration in its own right.

## ADR-030 — Hostnames are encoded the way browsers encode them: UTS-46, non-transitional, as the WHATWG URL Standard specifies

**Status.** Accepted 2026-10-09 (operator approved adding `idna`; the processing choice is this ADR's). Follows the D48 re-review.

**Context.** A hostname with non-ASCII characters is matched against a certificate in its A-label (punycode) form (RFC 9525 §6.3), so it must be encoded first. Until now both of `tls`'s readings encoded it with Python's built-in `idna` codec, which implements **IDNA 2003**. Our matcher called it directly, and `ssl` calls it on `server_hostname` before OpenSSL sees the name. For ß, ς, ZWNJ and ZWJ, IDNA 2003 gives a different A-label from what browsers use. `faß.de` became `fass.de` instead of `xn--fa-hia.de`. So both readings could agree on a false mismatch. The D48 re-review's stopgap made such names `inconclusive`.

**The choice: UTS-46 processing with Transitional_Processing=false, which is what browsers do, not strict IDNA 2008.**
- **What browsers do is specified.** The WHATWG URL Standard's domain-to-ASCII algorithm runs UTS #46 ToASCII with `Transitional_Processing` false, `CheckBidi` true and `CheckJoiners` true. The other parameters (`CheckHyphens`, `UseSTD3ASCIIRules`, `VerifyDnsLength`) follow its `beStrict` flag, which is false for ordinary URL parsing. Hostname matching should follow what real clients do (operator).
- **Where the two differ.** On ß, ς and the joiners, UTS-46 non-transitional and IDNA 2008 agree: ß stays ß, ς stays ς, and a joiner is allowed only where IDNA 2008's CONTEXTJ rule allows it, as after a virama in Indic scripts. Transitional processing was where ß became ss, and UTS #46 has deprecated it. What still separates UTS-46 from strict IDNA 2008 is **mapping**: UTS-46 case-folds and normalises input, so `BÜCHER.example` maps to `xn--bcher-kva.example`, while strict IDNA 2008 rejects the uppercase input. A browser maps it, so we map it.
- **Implementation:** the `idna` package (BSD-3-Clause), already a transitive dependency through `httpx` and `anyio`, now a direct one with a registry entry. We call `idna.encode(name, uts46=True)`. It applies UTS-46 mapping, then IDNA 2008 validity checks (CONTEXTJ, Bidi). Those checks are stricter than UTS-46 ToASCII in a few places, such as hyphen positions and some symbols.

**Decision.**
1. **One encoder**, `core.tls.a_label`. An ASCII name is only lowercased. A non-ASCII name goes through `idna.encode(name, uts46=True)`.
2. **Both readings use it.** Our matcher compares the A-label, and the A-label is what is passed as the SNI and as the name OpenSSL checks, so Python's IDNA 2003 codec never runs.
3. **A name that does not encode is `inconclusive`, never a mismatch.** That covers a joiner where CONTEXTJ forbids it, and anything else `idna` rejects. The name is invalid, and no client would get as far as checking a certificate. Where `idna` is stricter than UTS-46, this costs recall, never precision.
4. This replaces the D48 re-review's stopgap, which made every name containing ß, ς, ZWNJ or ZWJ `inconclusive`.

**Consequences.**
- `faß.de` matches a certificate for `xn--fa-hia.de`, for both readings, as in a browser. Indic-script names (`.भारत`, `.இந்தியா`), including a joiner after a virama, are tested.
- The shared IDNA 2003 blind spot recorded under D38 is gone. Both readings still share the encoder, now the right one. The encoder is input to both readings, not one of them.
- `tls` bumps its version, because results change for non-ASCII names.
- **Limit:** a name that does not encode is still connected to, with Python's IDNA 2003 encoding of it as the SNI. Only the hostname check refuses to judge it; the other TLS checks judge whatever server answered. No browser would connect to such a name at all. Making every TLS check `inconclusive` for an invalid name is the stricter fix, recorded and not yet built.

**Reversal cost.** Low: remove the call and go back to the stopgap.

## ADR-031 — Service hosts: read-only public endpoints, per target, and the RDAP bootstrap is vendored

**Status.** Accepted 2026-10-10 (operator), with a 90-day bootstrap freshness limit. Covers ledger D28. D31 needs no service host. The IANA bootstrap's data-licence entry was signed off by the operator on 2026-10-10. **Implemented 2026-10-10 by D28 (domscout v1.3.0)**; see "Implementation" below.

**Context.** `BaseScanner.service_hosts` (crt.sh, rdap.org) was added during Tool 3 without an ADR. D28: rdap.org is a bootstrap redirector. It answers `302` to the registry's own RDAP server, `core.http` rightly declines to follow a redirect out of scope, and domscout then parsed the empty body as "carries no expiration event". It has never read an expiry live, for any TLD.

**Decision.**
1. **A service host is a read-only public service.** GET only, never the target, passive in every mode. Each is declared in code with its purpose and the evidence for its behaviour. Rate limits and cost metering apply to it as to the target.
2. **Service hosts are per target.** An additive classmethod on `BaseScanner` returns the hosts for one target, and defaults to the static `service_hosts`. For domscout it returns crt.sh plus only the RDAP server for the target's TLD. So a `.in` scan's scope gains `rdap.nixiregistry.in` and no other registry.
3. **The registry's RDAP server comes from a vendored copy of IANA's bootstrap**, the "Bootstrap Service Registry for Domain Name Space", RFC 9224, `https://data.iana.org/rdap/dns.json`. It is matched label-wise, longest first (RFC 9224 §4). We query the registry directly and drop rdap.org, so there is no redirect to follow. RFC 9224 §8 says clients "SHOULD cache the registry": the vendored copy is that cache, and its refresh rule is the freshness limit.
4. **Freshness: 90 days**, from the file's own `publication` field. A test fails CI beyond that. **Why 90 days is safe:** a stale bootstrap fails to `inconclusive`, never to a false claim.
   - A TLD missing from it gets "no RDAP server in IANA's bootstrap" (RFC 9224 §7).
   - A server that has moved fails to fetch, or redirects out of scope. Either way, no expiry is read.
   - A stale entry can never make us assert an expiry date that the registry did not serve.
5. **An unfollowed redirect is reported as what happened**, never parsed as a body: "the registry's RDAP server redirected to `<host>`, which this scan may not contact, so expiry was not read".
6. **Service-host content is not target-served content.** ADR-029's exposure rule is unchanged.
7. **A fixture standing in for a service must be recorded, not invented** (ADR-027).

**Confidentiality.** **Service hosts learn which domains we scan.** crt.sh receives every target name in its query, and so will the registry's RDAP server for the target's TLD. That reveals that someone is examining the domain, at that time, from our address. It is the same kind of disclosure as any public DNS or registration lookup, but it is a disclosure about our customer's activity to a third party. Before beta it goes into customer-facing terms (ledger item, DPDP-relevant). Until then it is stated here.

**Rejected.**
- Following rdap.org's redirect to any host: the scope becomes unbounded.
- Following it only to bootstrap-listed hosts: this still needs the bootstrap, and adds a hop and a third party.

**Consequences.**
- domscout's expiry check can read live registries. **A TLD with no bootstrap entry stays `inconclusive`** (seen 2026-10-10: `.io`, `.भारत`/`xn--h2brj9c`, `.இந்தியா`). WHOIS (port 43) is out of scope.
- The bootstrap needs a data-licence registry entry. Evidence: the registry is listed on `iana.org/protocols` and IANA dedicates the Protocol Registries to CC0 1.0. IANA's licensing page does not name `data.iana.org` itself. The operator signs off.

**Reversal cost.** Low: the classmethod defaults to the static list.

**Implementation (D28, 2026-10-10).**
- `BaseScanner.service_hosts_for(target)` is the classmethod (clause 2). `cli/main.py` and `cli/corpus.py` build the HTTP scope from it. domscout's static list is now `crt.sh` alone.
- The bootstrap is vendored unmodified at `scanners/domscout/data/iana-rdap-dns.json` (`publication` 2026-09-30T23:00:03Z). The lookup is label-wise, longest first, on A-labels (ADR-030's encoder), and prefers https.
- **Special-use names** (operator ruling 2026-10-10) are read from IANA's Special-Use Domain Names registry (updated 2026-05-22). Expiry for them is `not_applicable` ([ADR-032](#adr-032--not_applicable-a-check-outcome-with-a-fixed-list-of-reasons)). **`example.com`, `example.net` and `example.org` are left out:** RFC 6761 reserves them, but a real registry holds each, with an RDAP record and an expiry, so "no registry delegates it" would be false.
- **Registries answer a name they do not hold differently** (seen live 2026-10-10, for a subdomain): Verisign answers `404`, PIR `400`, and **NIXI `200` with the registered domain's own record** (`ldhName` `nixi.in` for `www.nixi.in`). So the record's `ldhName` decides what a date is about. A date is reported under that name, and only when it is the target or an ancestor of it; any other name is `inconclusive`. A `400` or `404` is `inconclusive`, worded as "no registration for", with the Public Suffix List gap (D49) named.

---

## ADR-032 — `not_applicable`: a check outcome, with a fixed list of reasons

**Status.** Accepted 2026-10-10 (operator), with the two conditions below written in. An additive change to the frozen contract (`contracts/scanresult.schema.json`). It is reviewed with D28, its first user.

**Context.** D28's ruling (operator, 2026-10-10): a special-use name (RFC 6761) has no registry, so registration expiry does not apply to it. That must be **recorded as such in telemetry, never a silent pass**. The contract could not say it:
- `clear` is the silent pass the ruling forbids.
- `suppressed` means "below the reporting threshold" and carries a confidence.
- An informational finding needs a control-vs-test evidence pair for a query never sent.

**Decision.**
1. `CheckRun.outcome` gains `not_applicable`: the check cannot be asked about this target at all. `CheckRun` gains `reason`, present **exactly when** the outcome is `not_applicable`.
2. **Condition 1: no escape hatch.**
   - Reasons are a fixed list. They are registered in `core/applicability.py` with their wording, enumerated by the schema and mirrored by `core.models.NotApplicableReason`. Free text is refused by the model and by the schema.
   - Each scanner declares, per check in its `CHECKS` table (`not_applicable_reasons`), which reasons that check may give.
   - `core.applicability.not_applicable` is the only constructor, and it refuses an unregistered or undeclared reason.
   - A contract test (`tests/contract/test_not_applicable_contract.py`) runs every registered scanner over its corpus and fails if any `not_applicable` run's reason was not declared by its check, so a hard case cannot be renamed "not applicable" to step around the inconclusive gate.
   - Adding a reason amends this ADR and the schema.
3. **Condition 2: always visible, never a pass.**
   - It is outside the inconclusive rate's denominator (`ScanResult.inconclusive_rate`, `make corpus`), because it judged nothing.
   - It is **never a TP, FP or FN**: an expectation on a not-applicable check is neither met nor missed.
   - Every report shows its count: the `not-app` column in `make corpus`, a `not_applicable` field per tier and case in `corpus/results/*.json`, and `N not applicable` with each check and reason in `scan run`'s summary.
   - It can never close a finding: `scan verify` treats it as no verdict.
   - A `ScanResult` that reports a finding where the same check declared itself not applicable at the same location is invalid.
4. **Registered reasons:** `special-use-name` (D28: `domain-expiring` and `domain-expired`).

**Likely second user, not changed here:** D47, MTA-STS and TLS-RPT on a domain that accepts no mail (a null MX). It would need its own reason, declared by those checks, under an amendment of this ADR.

**Rejected.**
- Reusing `suppressed`: it bends a documented meaning.
- An informational finding: it has no honest evidence pair.
- A free-text reason: that is the escape hatch condition 1 closes.

**Reversal cost.** Medium. Removing the outcome means migrating stored results that carry it. Today only domscout's two expiry checks emit it.

