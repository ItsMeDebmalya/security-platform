# 02 — Decisions (ADRs)

*Every significant decision, why it was taken, what it costs to reverse. If you disagree with something here, this is the file to argue with — not the code.*

Status values: **Decided** · **Provisional** (decided but low-confidence, revisit at a named trigger) · **Open** (see [07-open-questions.md](07-open-questions.md))

| # | Decision | Status | Reversal cost |
|---|---|---|---|
| 001 | Tool-first build order | Decided | Low |
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
| 012 | Defer all platform/billing work to Phase 6 | Decided | Low |
| 013 | Measurement spec: gates are precision + recall + inconclusive rate | Decided | Low |
| 014 | Descope the moat claims to what 2 people can own | Decided | Low |
| 015 | Ownership verification exists from tool #1, not Phase 6 | Decided | Not reversible (legal) |

> **v3.1:** every factual claim in ADR-003 was checked against primary sources. Corrections are marked **[verified 2026-08]** or **[CORRECTED]** inline. Claims that could not be verified are marked **[UNVERIFIED]** rather than left to look settled.

---

## ADR-001 — Build tools first, platform second

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
