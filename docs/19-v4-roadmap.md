# Integrated Security Platform — Development Roadmap (Draft v1)

> **Current release scope is set by [ADR-033](02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred) and [docs/24-alpha-scope.md](24-alpha-scope.md) (12 October 2026), not by this document.** The first release is an **MVP Alpha**: customer Light scanning plus our internal server fleet assessed by the Linux agent, built to [docs/26](26-alpha-build-sequence.md). **The Linux agent is in the Alpha**, which supersedes this roadmap's exclusion of it from the MVP (§2) and its Phase 2 placement (§3). No new external scanners are added, the flow engine is minimal and deterministic, and Tool 4b is deferred past the Alpha. This roadmap is kept as written, as the record of the original plan.

**Companion to: Draft Plan (v4)**
*Prepared for initial review · updated 1 October 2026 to add the web presentation layer · to be refined on feedback*

---

## How to read this document

The Draft Plan answers **what** we are building and **why**. This roadmap answers **how, in what order, and with what**. It is deliberately a draft — timings, team assumptions and infrastructure choices are starting points for your feedback, not fixed commitments.

**Contents**
1. Guiding Principles
2. MVP Definition — what "first sellable version" means
3. Phased Implementation Plan
4. Milestones & Demo Points
5. Testing Strategy (with defect-recurrence prevention)
6. Infrastructure & Prerequisites
7. Web Presentation Layer (Dashboard)
8. Version Control, Branching & Backup Strategy
9. Development Workflow
10. Scalability Practices
11. Assumptions & Open Inputs

---

## 1. Guiding Principles

These shape every sequencing decision below.

| Principle | What it means for the roadmap |
|---|---|
| **Shared core first** | The evidence store, validation engine, confidence scoring and reporting are built once, early, because every feature depends on them. |
| **Defensive before offensive** | Safe, read-only capability ships first — it is sellable, low-risk, and builds trust before we introduce anything that touches a target aggressively. |
| **Compliance is foundational, not bolted on** | Retention, residency and access control are Phase 1, because they cannot be retrofitted (logs deleted are gone; residency dictates where we host). |
| **Each phase is independently demonstrable** | Every phase ends in something we can show and, from Phase 1, something we can sell. |
| **Accuracy is the product** | Testing and validation are first-class workstreams, not a final step. |
| **API-first** | Every capability is exposed as an API before it has a screen. The dashboard is a *consumer* of the API, never a place where logic lives. This is what makes the platform automatable and integration-ready later. |
| **The dashboard shows the truth** | The dashboard reflects real state from the API — a finished tool shows real output, an unbuilt one shows an honest "coming soon". We never fake a working feature. |

---

## 2. MVP Definition

The MVP is the **smallest version that is safe, sellable, and true to the core promise** ("if there is no proof, it does not count").

**In the MVP (end of Phase 1):**
- Defensive scanning: web, TLS, DNS/email, external exposure, external CVE
- The shared core: evidence store, validation, confidence scoring, reporting
- Light + Standard scan depths
- Asset ownership verification
- One-year log retention on India-resident storage
- Internal access-control model (zero standing access)
- Account, billing, Free + Pro tiers
- **Dashboard v1** — the web shell: login, scan launch, live scan progress, a findings view with evidence, and a roadmap page showing built vs coming-soon features

**Explicitly NOT in the MVP** (deferred to later phases, stated so scope does not creep):
- Offensive mode / attack simulation
- Authorization/RBAC and concurrency testing
- The Linux agent
- IoT, cloud, container coverage
- Assisted breach filing

**Why this line:** it is the largest slice that carries zero aggressive-testing risk, so it can go live while the authorisation, safety and legal framework for offensive testing is still being built.

---

## 3. Phased Implementation Plan

Durations are working estimates for a small team; treat them as relative sizing, not commitments.

### Phase 0 — Foundation Setup *(2–3 weeks, before feature work)*

The groundwork that everything else sits on. Small, but skipping it is what causes pain later.

- Git repository, branching model, and CI skeleton (Section 7)
- Base infrastructure provisioned (Section 6): India-region cloud project, secrets vault, database, object storage
- Backup and restore tested **before** any real data exists
- Skeleton app deploys through the pipeline to a staging environment
- **Dashboard shell + design system** scaffolded (layout, navigation, the "coming soon" placeholder component, theme)
- Tool registry started (every third-party tool logged with licence)
- **Exit check:** a "hello world" commit flows through CI to staging automatically, the dashboard shell renders with all future features as placeholders, and a backup can be restored.

### Phase 1 — Defensive MVP + Shared Core *(≈4–5 months)*

| Workstream | Delivers |
|---|---|
| Shared core | Evidence store, validation engine, confidence scoring, reporting |
| Defensive engines | Web, TLS, DNS/email, external exposure, external CVE |
| Scan depths | Light + Standard |
| Compliance base | 1-year retention, India residency, tiered storage, write-once security logs |
| Access control | Zero standing access, break-glass, immutable audit log |
| Incident readiness | Own-breach runbook + templates (CERT-In 6h / DPDP 72h) |
| Firewall (defensive) | WAF detection + reachability pre-check |
| Product shell | Accounts, ownership verification, billing, Free + Pro |
| **Dashboard v1** | Scan launch, live progress, findings + evidence view, roadmap page (built vs coming-soon) |

**Exit = the MVP is live and sellable, and the dashboard shows real scan output end to end.**

### Phase 2 — Authorization, Concurrency & Linux Agent *(≈3–4 months)*

| Workstream | Delivers |
|---|---|
| Flow engine v1 | Deterministic decision-tree engine |
| Multi-identity session manager | Holds 3+ concurrent identities — the shared prerequisite |
| Authorization / RBAC | Permission-matrix testing (object- and function-level, escalation, forced browsing, mass assignment) |
| Concurrency | Concurrent-session tests (read-only) + race/TOCTOU engine (state-affecting class) |
| Linux agent | Read-only inventory + patch state + log/backup/config permission collection |
| Data-at-rest review | Access + exposure hygiene checks (customer-side) |
| Firewall (offensive) | Effectiveness validation |
| Attack-path chaining v1 | First proven chains |
| Authorisation system | Scope agreement, allow-listing, opt-in gate |
| **Dashboard v2** | Permission-matrix view, attack-path visual, agent status page; offensive modules flip from "coming soon" to live |
| Tier | Business |

**This is where we become clearly different from defensive-only competitors.**

### Phase 3 — Depth & Compliance Completion *(≈4 months)*

- Full attack-path graph + chokepoint analysis
- Firewall differential testing (hidden vs fixed)
- AI/chatbot playbook; custom playbook builder
- Compliance readiness mapping (CERT-In, DPDP, ISO 27001, SOC 2, PCI DSS)
- Customer-visible access log
- Assisted breach filing *(gated on the liability/contract decision)*
- DPIA maintained; audit-ready evidence posture
- **Dashboard v3** — chokepoint graph view, compliance-readiness dashboard, exportable reports, customer access-log view
- **Target: DPDP full compliance well ahead of 14 May 2027**

### Phase 4 — IoT & Platform Expansion *(≈4–5 months)*

- IoT defensive suite (TEC 31318 / ETSI EN 303 645)
- IoT/OT offensive playbook (read-only proof; no live ICS)
- Cloud + container coverage
- In-application validation sensor (agent evolution)
- **Dashboard v4** — IoT/cloud/container views; those modules flip from "coming soon" to live

### Phase 5 — Enterprise & Scale *(≈5 months)*

- SSO, MSSP multi-client, internal network testing
- Windows agent *(on commercial trigger)*
- **Dashboard v5** — multi-tenant/MSSP client switcher, role-based views, white-label theming

**Visual sequence:**

```
Phase 0  Foundation  [==]
Phase 1  Defensive MVP + Core   [==========]  <- first sellable
Phase 2  Authz + Concurrency + Agent  [========]  <- key differentiator
Phase 3  Depth + Compliance complete  [=========]  <- DPDP deadline cleared
Phase 4  IoT + Expansion  [==========]
Phase 5  Enterprise + Scale  [==========]
```

---

## 4. Milestones & Demo Points

Each milestone is a concrete, showable thing — not "X% done."

| # | Milestone | Demo you can give | Phase |
|---|---|---|---|
| M0 | Pipeline live | A commit auto-deploys to staging; a backup restores | 0 |
| M0.5 | **Dashboard shell live** | The web dashboard opens, navigation works, every future feature shows as an honest "coming soon" tile — the whole vision visible on day one | 0 |
| M1 | First real finding | Scan a domain, show a TLS/DNS finding **with evidence** | 1 |
| M2 | Core proves itself | Same finding shown with a confidence score + re-test | 1 |
| M3 | **MVP live** | End-to-end in the dashboard: sign up → verify → launch scan → watch live progress → read the report | 1 |
| M4 | Flow engine walks a chain | Engine runs a playbook and unlocks the next check from a result | 2 |
| M5 | Authorization proof | Dashboard shows the permission matrix with a proven violated cell | 2 |
| M6 | Agent ground truth | Agent corrects a false-positive CVE the external scan flagged | 2 |
| M7 | First attack path | Dashboard renders two findings chained into one critical path | 2 |
| M8 | Chokepoint view | "Fix this one thing, N paths collapse" — shown as a graph | 3 |
| M9 | Compliance pack | Export a CERT-In/DPDP readiness evidence pack from the dashboard | 3 |
| M10 | IoT assessment | Scan a device, map to TEC 31318 gaps | 4 |

**The "coming soon" strategy:** from M0.5, the dashboard shows *every* planned feature — the built ones are live and clickable, the unbuilt ones are visible tiles marked "coming soon" with a one-line description. Stakeholders see the full ambition on day one, then watch tiles light up as each phase lands. Each phase's dashboard version (v1–v5) is the moment a batch of tiles flips from placeholder to live — a built-in, repeatable demo.

**Cadence suggestion:** a short demo at the end of each phase, plus a mid-phase demo for the longer phases (1, 3, 4). Each dashboard version is itself a natural demo and review gate for sir.

---

## 5. Testing Strategy

The goal is not just "test the code" — it is to **stop the same class of defect coming back**. Our own product's credibility rests on accuracy, so our internal testing has to model that.

### 5.1 Test layers

| Layer | What it covers | When it runs |
|---|---|---|
| Unit | Individual functions, parsers, scoring logic | Every commit (CI) |
| Integration | Engine ↔ core ↔ store working together | Every PR |
| End-to-end | Full scan flow on a known-vulnerable target | Nightly + pre-release |
| Regression | Every fixed bug has a test that locks the fix | Every PR |
| Security-of-us | Our own platform scanned (secrets, deps, config) | Every PR + nightly |
| Accuracy/calibration | False-positive & false-negative rate tracked over time | Weekly |

### 5.2 Deliberately-vulnerable test range

We stand up a controlled lab of intentionally broken apps (e.g. OWASP Juice Shop, DVWA, a custom app with a known IDOR and a known race condition) as **ground truth**. Every scanner change is measured against it: did detection improve, and did anything previously detected regress? This is how we measure accuracy objectively instead of by impression.

### 5.3 Preventing defect recurrence — the core discipline

This directly answers "mitigation of issues to prevent repetition." Every defect follows the same loop:

```
Bug found
   -> Write a failing test that reproduces it   (proves we understand it)
   -> Fix until the test passes
   -> Test is committed to the regression suite  (locks it forever)
   -> If it is a *class* of bug, add a lint/CI rule so it cannot recur
   -> Short root-cause note in the defect log
```

**The rule:** a bug is not "fixed" until a test exists that would have caught it. This makes regressions structurally hard rather than relying on memory.

### 5.4 Special testing concerns for this product

| Concern | Approach |
|---|---|
| Race-condition tests are timing-flaky | Require the divergence to reproduce across N runs before reporting; record the full request set as evidence |
| State-affecting tests change data | Run only against the deliberately-vulnerable lab in CI, never a real target; verify the cleanup report reverses state |
| False positives erode trust | Tracked as a first-class metric with a target threshold; a release that regresses it is blocked |
| AI must stay advisory | A test asserts the AI layer has no execution path — it can propose but never act |

### 5.5 Release gates

No release ships if: unit/integration tests fail, the regression suite fails, the false-positive metric regresses, a critical/high vulnerability exists in our own dependencies, or a backup restore has not been verified that week.

---

## 6. Infrastructure & Prerequisites

Beyond your existing Linux server, here is what the platform needs. Marked **[MVP]** = needed for Phase 1, **[later]** = needed by the phase noted.

### 6.1 Compute & hosting
- **[MVP]** Cloud project in an **India region** (residency is a legal requirement, not a preference)
- **[MVP]** Separate **staging** and **production** environments (never test on prod)
- **[MVP]** Container runtime (Docker) + orchestration (start simple; Kubernetes only when scale demands)
- **[MVP]** Scanner worker pool — isolated compute that runs scans, separate from the app
- **[later, P3]** GPU capacity for self-hosted LLM (Qwen3) — *or* a paid LLM API to start, decided at the compliance/cost review

### 6.2 Data & storage
- **[MVP]** Primary database (PostgreSQL) — findings, accounts, scope
- **[MVP]** Object storage for evidence + tiered log storage (hot/recent, cold/archive) — India-resident
- **[MVP]** **Secrets vault** (e.g. HashiCorp Vault / cloud KMS) with per-tenant keys — non-negotiable, we hold customer credentials
- **[MVP]** Cache/queue (Redis) for scan job scheduling

### 6.3 Scanning-specific
- **[MVP]** Dedicated **outbound scanner IP ranges** (static, publishable, so customers can allow-list us)
- **[MVP]** Out-of-band callback server (self-hosted) for proving blind findings safely
- **[P2]** Agent build + signing pipeline + update distribution channel (treated as supply-chain-critical)

### 6.4 Delivery & operations
- **[Phase 0]** Git hosting (GitHub/GitLab) with CI/CD
- **[Phase 0]** Artifact registry (container images)
- **[MVP]** Monitoring + logging + alerting (Grafana + Prometheus/Loki — aligns with your existing stack)
- **[MVP]** Error tracking (e.g. Sentry)
- **[MVP]** Automated backups with tested restores (Section 8)
- **[P3]** Status page + on-call rotation as customers grow

### 6.5 Dashboard / frontend (see Section 7 for detail)
- **[MVP]** Static hosting/CDN for the frontend, or serve it behind the API gateway
- **[MVP]** WebSocket or Server-Sent Events channel for live scan progress
- **[MVP]** API gateway / reverse proxy (routes dashboard + API, terminates TLS)

### 6.6 Non-technical prerequisites
- **[MVP]** Authorisation agreement + scope template (legal)
- **[P1]** Named internal privacy owner (DPDP)
- **[P3]** Contract position on assisted breach-filing liability
- **[ongoing]** Legal sign-off recorded per tool in the tool registry

---

## 7. Web Presentation Layer (Dashboard)

### 7.1 Feasibility verdict

**Feasible and low-risk — with one caveat.** A web dashboard is a standard, well-understood build; it adds no novel technical risk. The important discipline is that the dashboard stays a *thin client over the API* and never becomes where logic lives. The one real risk is **scope drift** — a dashboard can quietly absorb effort that belongs in the engines. We contain that by (a) keeping it API-first, so the dashboard can only show what the API already exposes, and (b) time-boxing each dashboard version to the phase it ships with.

Three concrete benefits, matching the strategic case:
- **Stakeholder experience** — sir and future customers see progress and output visually, not as terminal text.
- **Forces good architecture** — API-first is the correct production shape anyway; the dashboard makes us build it now rather than later.
- **Shows the modular vision** — the "coming soon" tiles make the whole platform legible on day one.

### 7.2 Recommended tech stack (lightweight, professional)

Chosen for small-team speed, a professional look without heavy design effort, and easy real-time data.

| Layer | Recommendation | Why |
|---|---|---|
| **Framework** | **React** (with **Vite**) or **Next.js** | Largest ecosystem, easy to hire for, component model fits a modular dashboard. Next.js if we want server-side rendering for a marketing/landing surface too. |
| **Language** | **TypeScript** | Type safety across the API boundary — fewer runtime surprises. |
| **UI components** | **shadcn/ui** + **Tailwind CSS** | Professional, modern look out of the box; no design team needed; fully themeable for later white-labelling. |
| **Charts / graphs** | **Recharts** (standard charts) + a graph library (e.g. **React Flow** or **Cytoscape.js**) for attack-path visuals | Covers both the KPI/score charts and the attack-path/chokepoint graph. |
| **Data fetching** | **TanStack Query** | Handles caching, loading/error states, and polling cleanly. |
| **Real-time** | **WebSocket** or **Server-Sent Events** | Live scan progress and findings streaming in as they are proven. |
| **Backend API** | **FastAPI** (Python) | Matches the engines' likely language; auto-generates OpenAPI docs; fast to build. |
| **Auth** | JWT / session via the API gateway | One auth path for dashboard and API. |

**Note:** this is a *product* frontend the customer will use and iterate on — so it is built as a proper React app in the repo, not as a one-off static page. It is deployed through the same CI/CD as everything else.

### 7.3 What the dashboard must contain

Grouped by priority so the MVP version is unambiguous.

**Dashboard v1 (MVP) — the essentials:**
- **Login / account** and asset management (add asset, verify ownership)
- **Scan launch** — pick a target and scan depth, start a scan
- **Live scan progress** — real-time view of which phase the scan is in
- **Findings view** — the prioritised list, each finding expandable to show its **evidence** (the proof), severity **and** confidence
- **Report view / export** — a clean, shareable result
- **Roadmap / features page** — the built-vs-coming-soon grid (the "living presentation")
- **Security score** — the headline number with sub-scores

**Added in later versions:**
- Permission-matrix view, attack-path graph, agent status (v2)
- Chokepoint graph, compliance-readiness view, customer access-log, richer reports (v3)
- IoT/cloud/container views (v4)
- Multi-tenant client switcher, role-based views, white-label theming (v5)

**Always present, from v1:**
- The **"coming soon" placeholder pattern** — every unbuilt feature is a visible, described tile, never a hidden gap
- Honest empty states — "no findings yet", "not tested", never a faked result
- Responsive layout — usable on a laptop in a meeting room

### 7.4 The "coming soon" milestone pattern

This is the mechanism that keeps stakeholders engaged across a long build.

```
Day one (M0.5):   [Web ✓][TLS ✓][DNS ✓] [Authz ⏳][Agent ⏳][IoT ⏳][Cloud ⏳] ...
                   built & clickable        "coming soon" tiles, each described

Each phase:        a batch of ⏳ tiles flips to ✓ and becomes live
                   -> that flip IS the demo for that phase
```

Rules that keep it credible with a technical audience:
- A tile is only marked ✓ (live) when it produces **real output from the API** — never a mock.
- Each ⏳ tile carries a one-line description and, optionally, its target phase — so it reads as a plan, not vaporware.
- Clicking a ⏳ tile shows what it *will* do, not a fake result.

**Why this works:** the first demo already shows the entire ambition of the platform, and every subsequent demo is visibly "more lights on." Progress becomes self-evident without a status report.

---

## 8. Version Control, Branching & Backup Strategy

### 8.1 Git repository structure

Start as a **monorepo** (one repo, clear folders) — simpler for a small team, easier to keep the shared core and engines in sync. Split into multiple repos only if the team grows enough that it becomes a bottleneck.

```
/core        shared engine (evidence, validation, scoring)
/engines     scanning modules (web, tls, dns, authz, ...)
/agent       linux agent
/api         backend API (FastAPI) — the API-first contract
/web         dashboard frontend (React + TypeScript + Tailwind/shadcn)
/infra       infrastructure-as-code, deploy configs
/tests       shared test harness + deliberately-vulnerable lab configs
/docs        this roadmap, the plan, runbooks
```

### 8.2 Branching strategy

**Trunk-based with short-lived feature branches** — recommended for a small, fast-moving team. Avoids the overhead of heavier models while staying safe.

| Branch | Purpose | Rule |
|---|---|---|
| `main` | Always deployable | Protected; no direct pushes; CI must pass |
| `feature/<name>` | One feature or fix | Short-lived (days, not weeks); branched off `main` |
| `release/<version>` | Stabilise a release | Cut when preparing a phase demo/release |
| `hotfix/<name>` | Urgent production fix | Branched off `main`, merged back fast |

**Rules that keep it clean:**
- Every change goes through a **Pull Request** — no direct commits to `main`
- PR requires: CI green + at least one review (even self-review with a checklist while solo)
- Small, frequent merges beat large ones (fewer conflicts, easier to review)
- Tag every release (`v0.1.0`, `v0.2.0`…) so you can always roll back to a known point
- Commit messages follow a simple convention (`feat:`, `fix:`, `test:`, `docs:`) for a readable history

### 8.3 Backup strategy

Follow the **3-2-1 rule**: 3 copies, 2 different media/locations, 1 off-site.

| What | How | Frequency | Retention |
|---|---|---|---|
| Database | Automated snapshots + point-in-time recovery | Continuous + daily snapshot | 1 year (matches log retention) |
| Evidence / object storage | Versioned, replicated to a second India region | Continuous | 1 year |
| Configuration / secrets | Vault backup (encrypted) | Daily | 90 days |
| Code | Git remote is itself a backup; mirror to a second host | On push | Indefinite |

**The rule that matters most:** a backup is not real until a restore has been tested. Schedule a **quarterly restore drill** and record it. Test the very first restore in Phase 0, before real data exists.

**Residency note:** all backups stay within India to satisfy CERT-In/DPDP — including the off-site copy (use a second India region, not another country).

---

## 9. Development Workflow

The day-to-day loop, kept lightweight:

```
Pick a task  ->  branch off main  ->  write test + code  ->
open PR  ->  CI runs (tests, security, lint)  ->  review  ->
merge to main  ->  auto-deploy to staging  ->  verify  ->
tag + promote to production
```

- **Definition of done:** code + test + docs updated + CI green + deployed to staging and verified.
- **CI runs on every PR:** unit + integration tests, dependency/secret scan, lint. Fast feedback keeps branches short.
- **Staging mirrors production** so "works on staging" means something.
- **Feature flags** for anything risky (especially offensive/state-affecting modules) — ship dark, enable deliberately.

---

## 10. Scalability Practices

Built in from the start so we do not have to re-architect later:

| Concern | Practice |
|---|---|
| Scan load grows | Scanners run as a **separate worker pool** behind a queue — scale workers independently of the app |
| Attack-path graph slows at scale | Incremental graph updates, bounded path depth (already a plan commitment) |
| Data grows | Tiered storage from day one; archive cold logs cheaply |
| Multi-tenant isolation | Per-tenant encryption and data separation from the first line of code — never retrofitted |
| Config sprawl | Infrastructure-as-code (everything reproducible, nothing hand-built) |
| Onboarding new engineers | Monorepo + docs + a one-command local setup |
| Model swap | AI stays advisory and abstracted, so Qwen3 ↔ paid API is a config change |
| Dashboard stays thin | API-first means the frontend holds no business logic — it scales as a static/CDN-served app independent of the engines |

---

## 11. Assumptions & Open Inputs

This draft assumes the following. Where an item is still open from the plan review, the roadmap flags where it lands so your decision slots straight in.

| Assumption / open input | Effect on roadmap | Status |
|---|---|---|
| Team size (assumed small, 2–4) | Drives all durations; trunk-based Git; monorepo | **Needs your input** |
| Cloud provider & India region | Section 6 infra choices | **Needs your input** |
| Self-hosted LLM vs paid API to start | Phase 3 GPU cost, or defer | Open decision from plan review |
| State-affecting test class approved | Whether the race engine stays in Phase 2 | Open decision from plan review |
| Assisted breach-filing liability | Whether M-assisted-filing stays in Phase 3 | Open decision from plan review |
| Target start date | Anchors the whole timeline | **Needs your input** |
| Frontend framework (React/Vite vs Next.js) | Section 7 stack; affects whether we get SSR for a marketing surface | **Needs your input** — React/Vite recommended unless a public marketing site is wanted |

**Timings are relative sizing, not commitments.** Once team size and start date are set, this converts into a dated plan.

---

*Draft v1 for initial review. Prepared as a companion to the Draft Plan (v4). All durations, team assumptions and infrastructure selections are starting points to be refined on your feedback.*