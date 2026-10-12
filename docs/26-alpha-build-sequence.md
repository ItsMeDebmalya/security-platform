# Alpha Build Sequence

**Project:** Integrated Security Platform (ProofScan → v4)
**Prepared:** 12 October 2026 · **Status:** Working plan
**Based on:** MVP Alpha Scope v2 · Alpha Scan Outcomes & Report Plan

Tick items with `[x]` as they complete. Each step ends with an exit check; don't start the next step until it passes.

---

## Ground rules for every step

- One task = one branch = one PR, merged with `--merge`.
- Anything touching `core/` or `contracts/` gets an **independent review** before merge.
- New checks are written test-first and must **fire on a real positive** (a lab box) before reaching the fleet.
- Corpus fixtures come only from **real recordings** (ADR-027). For the agent, a snapshot from a real lab box is the recording.
- Every new third-party component or data feed goes through the **licence registry** with a named sign-off.
- Plan first, approve, then build. No structural code without an approved spec.

---

## Agent architecture (decided in Step 2)

**A thin, one-shot collector.**

| Property | Alpha design |
|---|---|
| What it does | Collects facts only: packages, config values, ports, permissions |
| Where judgements happen | On the platform, in a `host` scanner using the existing contract |
| How it runs | Once, on demand, then exits. No service, no listener, no auto-update |
| Output | One snapshot file per host |
| How the platform receives it | Command-line ingest now; API upload after Step 7 |
| Data collected | Allowlisted settings only, never whole files; key fingerprints, not keys; secrets by type only |
| Commands it runs | A fixed allowlist of read-only commands, with fixed arguments and no shell |

**Later (after Alpha):** an always-on agent with outbound-only enrolment, signed updates and staged rollouts.

---

## Step 0 — Bring the decisions into the repo · 1–2 days

- [x] Add `docs/24-alpha-scope.md` and `docs/25-alpha-report-spec.md` (and this plan, docs/26); docs/25's data points reconciled against the scanner catalogue, agent data points marked PLANNED
- [x] ADR-033: combined Alpha; agent moves into Alpha; no new external scanners; minimal flow engine; AI summaries under a fact-check test; Tool 4b deferred (recorded against ADR-020)
- [x] Banner on `docs/19-v4-roadmap.md` pointing to ADR-033
- [x] CLAUDE.md CURRENT STATE and "Next" updated

**Exit:** ADR-033 merged; a new session reading CLAUDE.md knows the Alpha scope.

---

## Step 1 — Contract extension (Stage A) · 1–2 weeks

One deliberate, additive migration. All new fields optional, so existing findings stay valid.

- [ ] `host` target type (hostname / IP, reported by the agent)
- [ ] Vantage tag: external-unauthenticated · authenticated · agent
- [ ] Mode tag: defensive · offensive
- [ ] Finding links (one finding explains or chains to another), the basis for inside-out correlation
- [ ] State-affecting fields (what changed, cleanup record), defined now to avoid a second migration later
- [ ] ADR, schema + models, drift test green, independent review

**Exit:** contract supports host findings and links; all corpus baselines unchanged.

---

## Step 2 — Agent design · 3–5 days

- [ ] ADR-034: the architecture above
- [ ] Language decision (see "Decisions needed" below)
- [ ] Snapshot format, versioned
- [ ] Command and file allowlists, with the reason for each entry
- [ ] Data-minimisation rules, and a test that the snapshot never contains a secret value
- [ ] Vulnerability data source chosen, licence evidence gathered for sign-off
- [ ] Spec and implementation plan (`docs/superpowers/`)

**Exit:** ADR-034, spec and plan approved by Debmalya.

---

## Step 3 — Lab boxes · 3–5 days

- [ ] Containers for package and config modules (e.g. Ubuntu 20.04/22.04/24.04, Debian, a RHEL-family distro)
- [ ] At least one real VM for kernel, service and firewall modules (containers share the host kernel)
- [ ] Each box deliberately misconfigured to give real positives: root SSH login, password auth, autoindex on, database bound publicly, outdated package, pending reboot
- [ ] A matching **clean** box for negatives
- [ ] Lab images pinned by digest and in the licence registry

**Exit:** lab boxes reproducible from the repo.

---

## Step 4 — Collector v0, `host` scanner, ingest · 1–2 weeks

- [ ] Collector: OS release, kernel (running and installed), package list
- [ ] Snapshot written to a file; schema-validated
- [ ] `scanners/host/` implementing the contract, registered via `core/registry.py`
- [ ] Ingest: `scan run host --snapshot <file>`
- [ ] Snapshots from lab boxes recorded as corpus fixtures
- [ ] Collector tests: read-only, allowlist enforced, no shell, minimal data

**Exit:** a lab-box snapshot produces findings through the normal pipeline and the corpus gate.

---

## Step 5 — Modules · 6–9 weeks

Each module: spec section → tests first → collector fields → checks → lab positive and negative → corpus gate → catalogue updated.

- [ ] **1. Patch & vulnerability** (2–3 weeks): pending security updates; known vulnerabilities with distribution backports accounted for; data feed licence signed off
- [ ] **2. OS, kernel & reboot** (2–3 days): end-of-life distribution; newer kernel installed than running
- [ ] **3. SSH & access** (~1 week): root login, password auth, key types and sizes (fingerprints only), unrestricted sudo, extra UID-0 accounts
- [ ] **4. Services, firewall & correlation** (1–1.5 weeks): listening port → process; public vs local; host firewall; linked to external TLS/web findings for the same host
- [ ] **5. CERT-In readiness** (3–4 days): logging and audit enabled; retention vs 180 days; time sync against NIC/NPL servers
- [ ] **6. Web root cause** (~1 week): web server and PHP settings on disk, linked to the matching external web finding
- [ ] **7. Fleet view** (1.5–2 weeks): patch compliance %, hosts needing reboot, drift from fleet baseline, fleet-wide "fix this first"
- [ ] *If capacity:* Docker host posture; database/cache exposure (config only)

**Fallback if time runs short:** modules 1, 2 and 4.

**Exit:** every Alpha module WORKING on lab boxes; catalogue updated.

---

## Step 6 — Staged internal rollout · 2–3 weeks (overlaps Step 5)

- [ ] **Internal written authorisation** from the infrastructure owner, naming the servers — before the first production server
- [ ] Stage A: lab boxes only
- [ ] Stage B: 3–5 non-critical production servers; confirm no operational impact; hand-verify findings
- [ ] Stage C: the fleet, in batches
- [ ] Every finding on production servers kept out of git; findings reported to server owners

**Exit:** fleet snapshots ingested; live precision measured and hand-verified on a sample.

---

## Step 7 — API (Stage B) · 4–6 weeks

- [ ] FastAPI layer wrapping the scanners and core services, including host-snapshot upload
- [ ] Endpoints: launch scan, status, findings (with evidence and confidence), report
- [ ] Authorisation gate enforced at the API boundary
- [ ] Kill switch and cost tracking wired in

**Exit:** all scanners and snapshot ingest work through the API with gate-passing results.

---

## Step 8 — Reports · 5–7 weeks (partly parallel with Step 7)

- [ ] Report data model from stored results
- [ ] JSON (source of truth) → HTML → PDF, our branding
- [ ] Overall score and sub-scores, each traceable to findings
- [ ] Asset inventory including host inventory; server posture section; fleet summary
- [ ] AI summaries, labelled, with the mandatory fact-check test
- [ ] Tests: no secrets in any format, every statement traceable, same scan → same report

**Exit:** a lab-fleet run produces all three formats and passes every report test.

---

## Step 9 — Compliance foundations (Stage C) · 4–6 weeks (partly parallel)

Must be complete **before any external user**.

- [ ] One-year log retention, India-resident storage, tiered storage
- [ ] Internal access control: zero standing access, break-glass, immutable audit
- [ ] Secrets vault with per-tenant encryption
- [ ] Incident-response runbook (CERT-In 6h / DPDP 72h)

---

## Step 10 — Dashboard & accounts (Stage D) · 6–8 weeks

- [ ] Accounts via Chargebee (integration provided by Sir's track)
- [ ] Asset management; self-service Light scan
- [ ] Live progress, findings with evidence, reports, score
- [ ] Fleet view for internal servers
- [ ] Features page: built vs coming soon

---

## Step 11 — Minimal deterministic flow engine · 2–3 weeks

- [ ] Fixed playbooks over existing checks, declared dependencies
- [ ] AI explains; code decides; validator proves
- [ ] A test that the AI layer has no execution path

---

## Step 12 — Alpha launch gate · 1–2 weeks

- [ ] 0 BROKEN checks; every Alpha check WORKING or honestly UNDETERMINED
- [ ] Compliance foundations verified
- [ ] Report tests green; AI fact-check green
- [ ] Kill switch tested end to end
- [ ] Licence registry complete with sign-offs
- [ ] Sir's external items in place: Chargebee, authorisation flow for deep scanning

---

## Decisions needed

| Decision | Options | Lean |
|---|---|---|
| Collector language | Python standard library only, or a single Go binary | Python standard library only for Alpha: one language, easy to audit. Revisit if the fleet's Python versions vary too much |
| Vulnerability data | OSV.dev, distribution security trackers, or a combination | Decided in ADR-034 after licence evidence is gathered |
| Fleet OS mix | Needed from Debmalya | Determines lab box distributions and the collector's minimum Python version |

---

## Estimate

**About 7–9 months for one engineer**, with AI-assisted development. A second engineer is the most effective way to shorten it; the module fallback (1, 2, 4) is the second.
