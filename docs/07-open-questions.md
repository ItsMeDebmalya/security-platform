# 07 — Open Questions

*What is genuinely undecided, when it must be answered, and what happens if it is not. A question here is not a blocker unless marked as one.*

Legend: 🔴 blocks a phase · 🟡 needed during a phase · 🟢 can wait

---

## Strategy

### Q1 🟡 — When do we stop building tools and build the site?

The tool-first strategy ([ADR-001](02-decisions.md#adr-001--build-tools-first-platform-second)) defers all revenue and all real user feedback. That is a deliberate trade, but it needs a stopping rule decided in advance, because the temptation will be to keep polishing tools.

**Now more urgent:** Phase 2 was re-estimated from 8–12 weeks to 5–8 months, pushing a paid site to 18–24 months out. The cost of being wrong about demand has roughly doubled.

**Proposed rule:** at the end of Phase 2, if the Website Scanner Standard passes its gate, stop and evaluate. Options at that point are (a) continue to Phase 3 as planned, or (b) jump straight to Phase 6 with five proven tools and start earning. Option (b) is more attractive than it sounds — five accurate tools with evidence is already a better product than most of the market.

**Needed by:** end of Phase 2. **Decide:** founder.

### Q2 🟡 — Do we validate demand before Phase 6?

We will have working CLI tools for a year before anyone can buy anything. Cheapest mitigations, in rough order of value per effort:
- Run free scans manually for 10–20 target customers and hand-deliver the report. Also generates corpus labels.
- Publish the Email Security scanner as a free web page — one form field, one result. Small build, real signal.
- Open-source one narrow tool for credibility and inbound interest.

**Needed by:** during Phase 1, so the signal arrives before Phase 3 commitments. **Decide:** founder.

### Q3 🟢 — Pricing

Tiers (Free / Pro / Business / Enterprise) and the daily-credit model are sketched but no numbers exist. The ~75% gross margin target at Business tier is the constraint, and it depends on per-scan cost data we will not have until Phase 1 is running.

**Needed by:** Phase 6. **Depends on:** cost tracking from Phase 0.

---

## Legal

### Q4a 🔴 — GDPR and third-party data — **new, blocks Phase 3**

The plan has two features that process data about people and organisations who are not our customers and never consented:

- **OSINT harvesting** (A4) collects public employee names, emails and hosts. That is processing personal data about third parties. Lawful basis under Art. 6(1)(f) legitimate interest is arguable but not obviously sufficient, and **Art. 14 requires notifying data subjects when their data is collected from other sources** — practically impossible at the scale implied here.
- **Third-party / vendor risk scanning** (A15) scans companies who never consented, by design.

Also unresolved: retention limits on evidence bodies that incidentally capture customer production data, and a working **right-to-erasure** path — which must reach into object storage, not just the database.

**This blocks the OSINT and vendor-risk features specifically**, not the whole of Phase 3. Provisional retention table in [11-operations.md](11-operations.md). **Decide:** lawyer, before Phase 3.

### Q4b 🟡 — Legal exposure beyond licensing — **new**

Q4 below covers OSS licences only. The larger tail risks were on nobody's list:

- **CFAA / Computer Misuse Act.** Is DNS-TXT verification legally sufficient authorisation? It is reasonable effort, not case-law-tested immunity. A stale record, a subtenant, or a customer who lies still leaves exposure. The ToS must place the warranty of authority on the customer — but that is contractual, not criminal, protection.
- **Liability for a scan that breaks production.** No indemnification, liability cap, or insurance discussion exists anywhere, despite our own rate-limiting rules implicitly conceding the risk.
- **Passive third-party scanning** (A15) — lower risk than active, but not zero, particularly around abuse complaints.

**Needed by:** before the first paying customer. **Decide:** lawyer.

### Q4 🔴 — Legal review of the tool list

One review covering every approved open-source licence, recorded in `tools/registry.yaml`. ADR-003 is our own reading of these licences, and it needs to be a lawyer's reading before anything ships commercially.

**Blocks:** commercial launch (Phase 6). Not Phases 0–5. **Do now anyway:** maintain the registry from week one so the review is a one-day job rather than an archaeology project.

### Q5 🔴 — Terms of service and the authorisation agreement

Deep/Validated mode requires an explicit authorisation agreement from the customer. Standard mode requires verified ownership. Both need real legal wording, and the ownership-verification flow needs to produce an auditable record.

**Blocks:** any Standard scan against a customer asset — including manual ones done for Q2 validation. **Needed by:** the first customer scan, which may come well before Phase 6.

### Q6 🟡 — Breach / credential data provider

Requires a licensed provider (e.g. HIBP commercial API) and a legal review — handling breached credentials touches data protection law almost everywhere. We never scrape marketplaces or buy stolen data.

**Needed by:** Phase 5. **Do not build before the review.**

### Q7 🟢 — Jurisdiction and data residency

Where we incorporate and host affects GDPR obligations, what data we may store, and which enterprise customers we can sell to. Enterprise buyers will ask for residency choice.

**Needed by:** Phase 6 / 7.

---

## Technical

### Q7b 🟡 — Build or self-host the OOB server — **new**

ADR-008 committed to writing a Go OOB server. That objection was aimed at the *public* Interactsh instance and does not apply to self-hosting it — Interactsh is MIT, self-hostable on our own domain, and covers DNS/HTTP/HTTPS/SMTP. Fork, vendor, or build? Also unresolved: which DNS provider gives us programmatic control for the DNS-01 wildcard challenge.

**Needed by:** start of Phase 2. **Decide:** developer.

### Q7c 🟡 — The attack-path data model — **new**

`related_assets` is a cheap hedge, not a design. Relating findings across scanners about different entity types (subdomain → instance → IAM role → bucket) has no validated model yet, and the first draft wrongly asserted `target` + `location` was sufficient.

**Must be validated by end of Phase 3**, before any Phase 4 correlation work starts. If it turns out the schema cannot express it, that is a migration — the exact failure ADR-002 exists to prevent, arriving after the Phase 2 safety checkpoint.

### Q8 🟡 — Paid data API budget

Passive DNS (Censys or SecurityTrails) materially improves subdomain enumeration recall. VirusTotal and Google Safe Browsing serve reputation and malware checks. These are **data subscriptions, not tool licences**, so they are acceptable under ADR-003 — but they cost money and they become a per-scan cost that must fit the margin model.

**Needed by:** Phase 1 tool 3, for full recall. Free tiers and CT logs alone are enough to build and test against.

### Q9 🟡 — AI provider and cost model

The AI assistant explains findings, drafts remediation and summarises scans. Per-scan token cost feeds directly into gross margin, so the choice of model tier is a commercial decision as much as a technical one. Caching explanations per `check_id` (rather than per finding) is likely the single biggest cost lever.

**Needed by:** Phase 4. **Depends on:** cost tracking data from Phases 1–3.

### Q10 🟡 — Where do the scanners run?

Scanning from cloud provider IPs gets blocked and rate-limited by exactly the WAFs and CDNs we most need to scan through. Options: dedicated IP ranges we publish and defend; a residential/business proxy layer (raises its own ethical and legal questions); or accepting the blocks and reporting `inconclusive` honestly.

The last option is the most defensible and the least commercially attractive. Worth deciding deliberately rather than by default.

**Needed by:** Phase 2, when active scanning starts at volume.

### Q11 🟢 — Web framework, queue, and hosting

Deliberately unanswered ([ADR-009](02-decisions.md#adr-009--postgres-a-queue-and-object-storage-for-the-platform)). Postgres, a durable queue and object storage are settled in shape; the specific products are not. Deciding now would be guessing at requirements we do not have.

**Needed by:** Phase 6.

### Q12 🟢 — Do we ever port scanners to Go?

ADR-005 puts scanners in Python and the OOB server in Go. If a scanner turns out to be bound by Python-side concurrency rather than network wait, port that scanner behind the same contract. Nothing to decide until we measure.

**Needed by:** when a profile says so.

---

## Product

### Q12b 🔴 — testssl.sh or our own TLS engine — **new, blocks Tool 2**

[05-phase-1-first-tools.md](05-phase-1-first-tools.md) says start by shelling out to `testssl.sh` and parsing its JSON, replacing it later when its runtime becomes the bottleneck. That was written before Phase 0 existed. Two things have changed since, and both point the other way.

**What shelling out costs us.** testssl.sh is GPLv2, so it is separate-process-only forever — never linked, never adapted, enforced by the CI licence check. Its JSON schema broke between 3.0 and 3.2, so the version pin is load-bearing and every upgrade is a re-verification. It takes 1–3 minutes per host, which sets a hard ceiling on how many hosts a scan can cover. And its output is a *verdict*, not an observation — we would be parsing someone else's conclusions and re-deriving evidence from them, when evidence is the entire product thesis.

**What building costs us.** Python's `ssl` and `socket` give us certificate chains, protocol version negotiation and cipher enumeration directly. That covers the Light-mode surface and most of Standard. The parts that are genuinely hard are the vulnerability checks that need malformed input — and [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) already says we detect those by version and configuration inference rather than by sending them, so we were never going to use testssl.sh's implementations of them anyway.

**The asymmetry:** our own engine gives us the control-vs-test evidence pair for free, because we made the observation. Wrapping testssl.sh means reverse-engineering evidence out of its verdicts to satisfy our own contract.

**Options.** (a) Wrap testssl.sh as planned, replace later. (b) Build our own from the start. (c) Build our own, and keep a testssl.sh comparison harness in the corpus as an independent cross-check — the same role a second resolver plays in the email scanner.

**Needed by:** before Tool 2 starts. **Decide:** developer.

### Q13 🟡 — Does the free Light Scan need no signup at all?

The original plan says yes, and it is described as the major conversion driver. It is also an abuse vector: free unauthenticated scanning of arbitrary domains, from our IPs, at our cost.

Mitigations to choose between: aggressive per-IP rate limits, a captcha, results shown but a signup required to export or persist them, or a small daily quota per IP. The trade is conversion against abuse and cost.

**Needed by:** Phase 6, or Q2 if we ship the free Email scanner early.

### Q13b 🟡 — Verified-tool status — **new**

Three approved tools were never independently verified: **garak** and **PyRIT** (production maturity, API stability, whether they are usable as libraries or research toys) and **Amass** (recent maintenance health; licence is confirmed fine). The Apache-2.0 claims for Checkov, KICS, Prowler, Trivy, Syft and Grype were carried over from the plan rather than re-checked against current LICENSE files.

**Needed by:** before each is first used. Cheap to close — an afternoon of reading LICENSE files and commit logs.

### Q13c 🟢 — The Tool Coverage Matrix — **new**

Referenced by v2 as a companion document, not present in this repository. It held the full tool-by-tool competitor mapping. Find it or recreate it.

### Q14 🟢 — Do we open-source anything?

An open-source scanner or the payload library would build credibility fast in a market where practitioners are the buyers. It also hands competitors our detection logic. The confidence engine and the labelled dataset are the things that must never be open-sourced — those are the moat.

**Needed by:** no deadline. Worth deciding before we accidentally decide by inertia.

---

## Answered, recorded here so they are not re-litigated

| Question | Answer | Where |
|---|---|---|
| Do we embed Nmap / Nessus / Burp? | No. Build our own, import their output. | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| Do we do exploitation to prove findings? | No. OOB callbacks instead. | [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) |
| What language? | Python for harness and scanners; Go for the OOB server. Provisional. | [ADR-005](02-decisions.md#adr-005--python-for-the-harness-and-most-scanners-provisional) |
| Platform first or tools first? | Tools first. | [ADR-001](02-decisions.md#adr-001--build-tools-first-platform-second) |
| Semgrep or Opengrep? | Opengrep, with our own rules. Semgrep's rule licence forbids competing SaaS use. | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| Can we use GPL tools? | Yes, as separate processes only. Never linked, never copied. | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| Do we say "compliant"? | Never. "Compliance readiness" only. | [ADR-011](02-decisions.md#adr-011--compliance-readiness-never-compliance) |
| Is chokepoint analysis our moat? | **No — cut.** Wiz/XM Cyber's core product; also depends on Phase 5 data. Phase 4 ships basic correlation. | [ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own) |
| Do we build reachability analysis? | **No — cut.** Endor Labs' whole product. Direct-dependency matching only, stated plainly. | [ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own) |
| Is our BOLA testing novel? | No, not since Dec 2025. Build it; stop claiming novelty. | [ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own) |
| How is `inconclusive` counted in the gates? | Excluded from both sides, capped at 15%. | [ADR-013](02-decisions.md#adr-013--accuracy-gates-are-precision-recall-and-inconclusive-rate) |
| When does ownership verification get built? | Before the first Standard-mode check, not Phase 6. | [ADR-015](02-decisions.md#adr-015--ownership-verification-exists-from-tool-1-not-phase-6) |
