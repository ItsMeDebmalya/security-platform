# MVP Alpha — Scope & Direction (v2)

**Project:** Integrated Security Platform (ProofScan → v4)
**Prepared for:** Sir's review · 12 October 2026
**Status:** Signed off 12 October 2026; recorded as ADR-033

---

## 1. Summary

We are prioritising an **Alpha release to accelerate deployment**. External requirements (account management via Chargebee, and authorisation via DNS-TXT records + signed agreements for deep/offensive scanning) are owned by Sir. Engineering focuses on the core system.

**Decisions taken in this version:**

| Item | Decision |
|---|---|
| Release shape | **One combined Alpha release**: customer-facing scanning and the internal server fleet ship together |
| Flow engine | **Minimal and deterministic** for Alpha; full offensive engine staged later |
| New capability | **Server modules inside the agent**, not additional external scanners (Section 5) |
| Rollout | **Staged**: lab boxes → a few non-critical servers → the fleet |

---

## 2. What exists today (honest baseline)

- **Four accuracy-gated scanners:** Email, TLS, DNS/Subdomain, Web (Light).
- The checks read public information and change nothing. Most run in **Light** mode. Email and TLS add **Standard** checks that are declared passive too (ADR-023). Four TLS checks run through testssl.sh sent active probes until ledger D56 was fixed (12 October 2026, PR #44). Since D59 they do not run outside the lab at all: they can send hellos that name no site, which on a shared address reach someone else's, and we cannot yet show an address is dedicated to the customer. *(Corrected 12 October 2026 against [the regenerated scanner catalogue](21-scanner-catalogue.md): not every check is Light, and not every check is passive in practice.)*
- A **shared core**: evidence store, confidence scoring (separate from severity), honest finding states (incl. "inconclusive"), validation, kill switch, rate limiting, secret redaction, an authorisation gate.
- A completed **correctness audit**: 0 checks known to make false claims (0 BROKEN), and every change to the shared core independently reviewed before merge. *(Corrected 12 October 2026: scanner-only fixes such as D53 are reviewed only when they touch the core, by the operator's rule.)*

**Not yet built:** the offensive flow engine, Standard/Deep modes in production, the inventory agent, the API, the web dashboard, account management.

---

## 3. The combined Alpha

One release containing:

- **Customer-facing scanning, no signed agreement needed** ([ADR-033](02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred), decision 8):
  - **any domain:** Light checks only;
  - **an owner verified by DNS TXT:** Light plus the passive Standard checks, except the four testssl.sh checks, which need an address shown to be dedicated to the customer and are unavailable until that can be established (ADR-033 decision 8, D59).

  Self-service via the dashboard, accounts (Chargebee), shareable reports. Deep/offensive scanning, and the signed agreement that gates it, follow after Alpha. *(Clarified 12 October 2026: "Light only" meant "no authorisation needed", not literally Light mode.)*
- **Server assessment for Codezin's own fleet:** the read-only agent with the modules in Section 5, covered by one internal written authorisation.

**Note on timing:** a combined release ships when its slowest component (the agent) is ready. To keep momentum, the agent runs on lab boxes and a few internal servers **before** launch as internal validation; everything is then released together.

---

## 4. The three core pillars for Alpha

| Pillar | Status | Alpha scope |
|---|---|---|
| **Core agentic flow engine** | Not built; highest-risk component | A **minimal, deterministic** version: a fixed decision tree over existing checks, with AI *explaining* findings, never deciding. |
| **Safety & guardrails** | Largely built | Integration: wire the kill switch and cost tracking into the API; exercise the authorisation gate against a real scan for the first time. |
| **Deterministic accuracy** | Strong and ongoing | Continue moving unverified checks to "working" via live verification; hold the zero-false-claim bar. |

**Guiding rule, unchanged:** *AI proposes, code confirms.* AI advises and explains; it never takes an action or issues a verdict.

---

## 5. Server assessment modules (inside the agent) — all PLANNED, not built

All modules are **read-only**, collect the **minimum data** needed, and **suggest** fixes without ever applying them.

**The differentiator:** combining the inside view (the agent) with the outside view (the scanners). An external tool can see an open port; this platform can say *why* it is open, whether the firewall allows it, and which configuration line to change.

### Alpha modules (priority order; every module and data point below is PLANNED)

| # | Module | What it reports |
|---|---|---|
| 1 | **Patch & vulnerability** | Installed packages, pending security updates, known vulnerabilities, with distribution backports taken into account |
| 2 | **OS, kernel & reboot status** | End-of-life distributions; kernel updated but the old one still running |
| 3 | **SSH & access hardening** | Root login, password authentication, weak or old SSH keys (fingerprints only), unrestricted sudo, extra UID-0 accounts |
| 4 | **Services, firewall & inside-out correlation** | Each listening port and its process, public vs local binding, host firewall status, matched against the external scan |
| 5 | **CERT-In readiness** | Logging and audit enabled, log retention against the 180-day requirement, time synchronisation against NIC/NPL servers |
| 6 | **Root cause for web findings** | Web server and PHP configuration on disk (directory listing, version disclosure, TLS settings), pinpointing the exact setting to change |
| 7 | **Fleet view** | Patch compliance %, hosts needing a reboot, drift from the fleet baseline, "one update fixes N findings on M hosts" |

**If capacity allows:** Docker host posture (socket permissions, privileged or root containers) and database/cache exposure (MySQL, PostgreSQL, Redis bound publicly or without authentication, read from config only).

**After Alpha:** file-integrity monitoring, rootkit indicators, SUID inventories, kernel hardening parameters, scheduled-task audits.

### Rules for every module
- Must detect a real positive on the lab boxes before it reaches the fleet.
- Never reads file contents beyond what proves the finding; never logs in to databases or services.
- Secrets are reported by type only, never stored; key material is recorded as fingerprints only.
- Benchmark content (e.g. CIS) is licence-checked before its text or identifiers appear in the product.

---

## 6. Scanners — do we need more?

**No new external scanners for Alpha.** Four is enough. New value goes into the server modules above, which deepen visibility on the servers we are actually deploying to.

---

## 7. Rollout plan (~50 servers)

1. **Free lab boxes:** every module must fire on a real positive here first.
2. **A few non-critical production servers:** confirm no operational impact.
3. **The full fleet:** with the kill switch wired and the infrastructure owner in the loop.

Internal written authorisation is obtained **before the first production server**.

---

## 8. Authorisation agreement — contents for the lawyer

For deep/offensive and automated/unattended testing, the signed agreement must specify:

- **Named assets:** exact domains/IPs in scope, and what is explicitly out.
- **Explicit permission for automated, unattended testing:** generic "penetration testing" consent may not cover a system deciding its own next step.
- **Permitted intensity tiers:** Light / Standard / Deep, named.
- **Acknowledgement of state-affecting tests:** consent to tests that create records, and to test accounts being used.
- **Time window:** when testing may run.
- **Signer's attestation of authority:** "I am authorised to consent on behalf of X."
- **Emergency contact + kill-switch acknowledgement.**
- **Liability, indemnity, confidentiality:** the protective clauses.
- **Data handling (DPDP):** what we do with findings.
- **Agent consent:** permission to install software on hosts, what it collects, and retention.
- **Sub-processor disclosure (DPDP):** third parties receiving data, including Chargebee and the services scanners use (crt.sh, RDAP).

---

## 9. Reporting (summary)

Reports are generated deterministically from stored findings, in **JSON, HTML and PDF**, under **our branding**, with an **overall score plus sub-scores by area**. **AI-written summaries are included in Alpha**, labelled as such, and tested against the findings so they can never add or change a fact. Shared links are optional. Full detail: *Alpha Scan Outcomes & Report Plan*.

---

*Signed off 12 October 2026 and recorded as [ADR-033](02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred). Aligns with the v4 plan's core vision (proof-first, AI-proposes/code-confirms, defensive-first, MVP-first). The working build plan is [docs/26](26-alpha-build-sequence.md).*
