# Security Platform — Release Roadmap (MVP → Alpha → Beta → v1.0)

> **ARCHIVED, 12 October 2026. Superseded by [ADR-033](../02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred) and [docs/24-alpha-scope.md](../24-alpha-scope.md).** Kept as the record of the release plan of 6 October 2026; it is not maintained. ADR-033 changes it in three ways: the Linux agent moves from Post-1.0 (§6) into the Alpha; Tool 4b is deferred past the Alpha under this document's own §10, lever 4; and owners verified by DNS TXT get passive Standard checks in the Alpha. Current planning follows [docs/26-alpha-build-sequence.md](../26-alpha-build-sequence.md).

**Project:** ProofScan → v4 Integrated Security Platform
**Prepared:** 6 October 2026 · **Status:** Draft for review and adjustment

---

## How to read this document

This maps the technical work onto **release milestones** — what ships, to whom, and when. Each release has a defined audience, a feature set, explicit exclusions, and exit criteria.

**All timelines are estimates for adjustment, not commitments.** The assumptions they rest on are stated in Section 6 — change an assumption and the dates move predictably.

---

## 1. Release Ladder at a Glance

| Release | Audience | Core question it answers | Scan modes | Effort | Indicative date |
|---|---|---|---|---|---|
| **MVP** | Internal only | "Does the whole pipeline work end to end?" | Light + Standard (own assets) | ~22–31 weeks | Q1–Q2 2027 |
| **Alpha** | Invited friendly users | "Do people actually want this?" | **Light only** | +6–8 weeks | Q2–Q3 2027 |
| **Beta** | Limited external, paying | "Will people pay, and does it hold up?" | Light + Standard | +8–10 weeks | Q3–Q4 2027 |
| **v1.0** | Open signup | "Can we run this as a business?" | Light + Standard + Deep | +8–12 weeks | Q4 2027 – Q1 2028 |
| **Post-1.0** | Existing customers | Differentiating capability | + Offensive mode | Ongoing | 2028 |

**Total to v1.0: approximately 11–15 months of engineering effort.**

---

## 2. MVP — Internal Proof of the Full Pipeline

> **Goal:** one complete journey works end to end — launch a scan from a browser, watch it run, read a proven finding with its evidence, export a report. Nobody outside the team uses it.

**Audience:** internal only. No external users, no real customer data.

### Features in scope

**Scanning**
- [ ] Four accuracy-gated scanners: Email, TLS, DNS/Subdomain, Web Light
- [ ] AI/agent exposure checks (Tool 4b)
- [ ] Merged `scan all` command across all scanners
- [ ] Light and Standard scan depths

**Platform**
- [ ] Extended findings contract (attack-path linkage, state-affecting, mode/vantage tags)
- [ ] REST API wrapping all scanners and core services
- [ ] Auto-generated API documentation
- [ ] Scan launch, status, findings and report endpoints

**Interface**
- [ ] Web dashboard: login, scan launch, live progress
- [ ] Findings view with evidence and confidence
- [ ] Report view and export
- [ ] Features page (built vs. coming-soon)

**Foundations**
- [ ] One-year log retention, India-resident storage
- [ ] Internal access-control model (zero standing access, audit log)
- [ ] Secrets vault with per-tenant encryption
- [ ] Incident-response runbook

### Explicitly NOT in MVP
Offensive mode · authorization/RBAC testing · concurrency testing · the Linux agent · IoT, cloud and container coverage · billing · public signup

### Exit criteria
- [ ] All scanners runnable via API, returning gate-passing results
- [ ] Full browser journey works: sign in → verify asset → scan → report
- [ ] Test suite green; accuracy metrics holding
- [ ] Compliance foundations in place and verified

**Effort: ~22–31 weeks.** Breakdown in Section 5.

---

## 3. Alpha — Demand Validation

> **Goal:** find out whether people want this, using the legally simplest version. This is the demand test the project has deferred twice.

**Audience:** 10–30 invited users — friendly contacts, target-profile companies. Free.

### Why Alpha is Light-mode only

Light scans are **passive**: they read public information only and need no ownership verification and no signed authorisation. That means Alpha can launch **without waiting on the legal work** that gates Standard scanning. It is the fastest honest route to real-world signal.

### Features in scope
- [ ] Self-service signup and account management
- [ ] Light scan on any domain, no authorisation required
- [ ] Shareable result report
- [ ] Onboarding flow and first-run guidance
- [ ] Feedback capture (in-product)
- [ ] Usage analytics (scans run, repeat usage, drop-off points)
- [ ] False-positive reporting mechanism

### Explicitly NOT in Alpha
Standard/Deep scans for external users · billing · public signup · offensive mode

### Exit criteria
- [ ] 10+ active users having run a real scan
- [ ] Qualitative feedback gathered from at least 5
- [ ] False-positive rate measured against real-world targets
- [ ] A clear read on whether proof-first findings land with users

**Effort: +6–8 weeks after MVP.**

### What Alpha is really for
Three of the project's recorded open questions get answered here, and only here: whether there is demand, whether the proof-first differentiator matters to users, and what the real-world false-positive rate is. No amount of further building answers them.

---

## 4. Beta — First Paying Customers

> **Goal:** prove people will pay, and that the platform holds up under external use on assets we don't own.

**Audience:** 20–50 external users, paying. Invite-managed.

### ⚠️ Critical dependency

Beta **cannot start** until the legal work is complete: **terms of service and the authorisation agreement**. These gate every Standard scan of a customer's assets. This is a recorded blocker, and it is not solved by engineering.

**This work must start in parallel now, not when Beta approaches.** It is the single most likely cause of a Beta slip.

### Features in scope
- [ ] Asset ownership verification (DNS record / file / meta tag)
- [ ] Standard scan for verified assets
- [ ] Signed authorisation agreement flow
- [ ] Billing: Free and Pro tiers
- [ ] Scan scheduling and history
- [ ] Email alerts and notifications
- [ ] Support channel and documented SLA expectations
- [ ] Published scanner IP ranges

### Explicitly NOT in Beta
Offensive mode · the Linux agent · enterprise features (SSO, multi-client)

### Exit criteria
- [ ] Terms of service and authorisation agreement signed off by legal
- [ ] 10+ paying customers
- [ ] 30 days of stable operation without a critical incident
- [ ] Billing verified end to end
- [ ] Support load measured and sustainable

**Effort: +8–10 weeks after Alpha** *(engineering only — legal runs in parallel and may dominate)*

---

## 5. v1.0 — General Availability

> **Goal:** open signup, sustainable operation, deep validated scanning as the paid differentiator.

**Audience:** open public signup.

### Features in scope
- [ ] Deep / Validated scan mode (the proof tier)
- [ ] Business tier
- [ ] Compliance readiness mapping (CERT-In, DPDP, ISO 27001, SOC 2, PCI DSS)
- [ ] Attack-path chaining v1
- [ ] Fix verification (free re-test)
- [ ] Import findings from other tools
- [ ] Public documentation and status page
- [ ] Monitoring, alerting and on-call

### Exit criteria
- [ ] Open signup live and stable
- [ ] Confidence calibration validated against accumulated real outcomes
- [ ] Unit economics measured per scan
- [ ] Compliance posture audit-ready

**Effort: +8–12 weeks after Beta.**

---

## 6. Post-1.0 — Differentiating Capability

These are the capabilities that separate the platform from conventional scanners. Each is additive, built as a module on the stable contract.

| Capability | Why it matters | Indicative |
|---|---|---|
| **Authorization / RBAC testing** | Where real breaches happen; most tools cannot do it | 2028 H1 |
| **Concurrency testing** | A defect class single-request scanners structurally miss | 2028 H1 |
| **Offensive mode + flow engine** | Proves exploitability rather than listing possibilities | 2028 H1–H2 |
| **Firewall differential testing** | Distinguishes genuinely fixed from merely hidden | 2028 H2 |
| **Linux agent** | Ground-truth patch state; removes the largest false-positive source | 2028 H2 |
| **IoT / OT coverage** | Fast-growing, under-tested surface | 2028 H2 |
| **Chokepoint analysis** | Answers "what one fix helps most" | 2028 H2 |

---

## 7. Effort Breakdown

| Work item | Estimate | Notes |
|---|---|---|
| Tool 4a — Web Light | 3–4 weeks | **In progress** — spec approved, 15 tasks planned |
| Tool 4b — AI/agent exposure | 3–4 weeks | Own spec + ADR on probe passivity |
| `scan all` merged command | ~1 week | Closes Phase 1 |
| Contract extension | 1–2 weeks | Small but high-care; done once |
| API layer | 4–6 weeks | Wraps existing scanners; no new scan logic |
| Compliance foundations | 4–6 weeks | Partly parallelisable with API |
| Dashboard v1 | 6–8 weeks | Largest single MVP item |
| **MVP subtotal** | **22–31 weeks** | |
| Alpha readiness | 6–8 weeks | Onboarding, analytics, feedback |
| Beta readiness | 8–10 weeks | Verification, billing, support |
| v1.0 readiness | 8–12 weeks | Deep mode, compliance mapping, ops |
| **Total to v1.0** | **44–61 weeks (~11–15 months)** | |

---

## 8. Critical Path and Parallel Tracks

**Sequential (engineering):**
```
Tool 4a → Tool 4b → scan all → Contract → API → Dashboard → MVP
                                     ↘ Compliance ↗  (partly parallel)
```

**Parallel tracks that must start now — these are the real schedule risks:**

| Track | Why it must start early | Blocks |
|---|---|---|
| **Terms of service + authorisation agreement** | Legal lead time is outside our control | **Beta entirely** |
| **Licence review of all tools** | Required before any external use | Alpha |
| **Infrastructure provisioning** (India region, vault, storage) | Compliance foundations depend on it | MVP |
| **EOL / fingerprint data verification** | Data honesty; ongoing maintenance | Tool 4a gate |

> **The single biggest schedule risk is not engineering.** It is the legal work gating Beta. Starting it now costs little; starting it late stops the release.

---

## 9. Assumptions

Change any of these and the timeline moves predictably.

| Assumption | Current basis | Sensitivity |
|---|---|---|
| Team size: 1–2 engineers with AI-assisted development | Present arrangement | **High** — a second full-time engineer could compress MVP by ~30% |
| No major contract rework after Stage A | Contract designed once, additively | Medium |
| Compliance infrastructure available when needed | Not yet provisioned | Medium |
| Legal work proceeds in parallel from now | Not yet started | **High** — the main Beta risk |
| Accuracy gates pass first time | 3 of 3 have so far | Low–medium |
| No scope added mid-stage | Guardrails in place | Medium |

**Regulatory fixed point:** DPDP full compliance is due **14 May 2027**, which falls around the MVP window. The compliance foundations are scheduled before that date by design, not coincidence.

---

## 10. Adjustment Levers

If the timeline needs to compress, these are the honest options, best first:

1. **Add engineering capacity.** The most effective lever; MVP is capacity-bound, not knowledge-bound.
2. **Narrow the MVP dashboard.** Ship a thinner first interface — findings list and report only — and defer polish to Alpha.
3. **Start Alpha before the full dashboard.** Light-mode results could be delivered as reports while the interface matures.
4. **Defer Tool 4b** past MVP, closing Phase 1 with three and a half scanners. *Costs a recorded commitment (ADR-020) — only with a deliberate decision record.*

**Not recommended as levers:** cutting accuracy gates, cutting compliance foundations, or starting Beta before the legal work lands. Each trades a durable asset for a short-term date.

---

*Release roadmap, draft for review. Estimates are planning ranges, not commitments; adjust the assumptions in Section 9 and the dates follow.*
