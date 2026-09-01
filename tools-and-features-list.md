# Security Platform — Build Plan

### Version 3.4 — the plan as it now stands, with two tools shipped against it

**What this is:** a security scanning platform. Users point it at assets they own and get findings that are **proven, dated, and connected** — not guessed. Market reference point: armorist.ai and similar.

**The strategy, in one line:** build and prove scanners one at a time from the command line, then wrap the proven shelf in a website. Not the other way around.

**Where we actually are:** Phase 0 and Phase 0b are complete. **Tools 1 (Email) and 2 (TLS) both pass their accuracy gates.** Everything below is either built, or honestly labelled as not built.

---

## Start here

| Read this | If you want |
|---|---|
| **[docs/14-progress-ledger.md](docs/14-progress-ledger.md)** | **What actually happened** — built, broken, fixed, owed. Read before anything else. |
| **[SPEC.md](SPEC.md)** | **The canonical build specification** — what each tool must do, its status, its gate. The authority on WHAT to build. |
| **[docs/00-context.md](docs/00-context.md)** | The product, the strategy, and the standard everything is held to |
| **[docs/01-architecture.md](docs/01-architecture.md)** | The Scanner Contract, the finding model, evidence, confidence, the asset graph |
| **[docs/02-decisions.md](docs/02-decisions.md)** | Every decision (ADRs 001–022), its reasoning, and what it costs to reverse |
| **[docs/03-roadmap.md](docs/03-roadmap.md)** | Phase by phase, tool by tool, with accuracy gates |
| **[docs/12-cli-runbook.md](docs/12-cli-runbook.md)** | How to actually operate the thing |
| **[docs/15-iot-scanner.md](docs/15-iot-scanner.md)** | The IoT & Device Security Scanner and its stop-the-line safety rules |
| **[docs/16-learning-map.md](docs/16-learning-map.md)** | What a developer new to this needs to learn, and when |
| **[docs/reference/product-spec.md](docs/reference/product-spec.md)** | The full catalogue — every tool, every feature, what each detects |
| **[docs/archive/](docs/archive/tools-and-features-list-v2.md)** | The original v2 proposal, unchanged and never edited |

Also: [04](docs/04-phase-0-foundations.md) and [05](docs/05-phase-1-first-tools.md) task lists, [06 guidelines](docs/06-guidelines.md), [07 open questions](docs/07-open-questions.md), [08 changelog](docs/08-changelog.md), [09 ownership verification](docs/09-ownership-verification.md), [10 measurement](docs/10-measurement.md), [11 operations](docs/11-operations.md), [13 test targets](docs/13-test-targets.md).

---

## The plan at a glance

| Phase | Name | Rough time | Ends with | Status |
|---|---|---|---|---|
| **0** | Foundations | 3–4 weeks | A skeleton that runs a scanner end to end | **done** |
| **0b** | Foundation for the calendar | — | Dates, the asset graph, replay, verify, correlation | **done** |
| **1** | The cheap accurate tools | 4–6 weeks | Email, TLS, DNS enum, Web Light — each at its gate | **2 of 4** |
| **2** | The hard one | 5–8 months | OOB callback server + Website Scanner Standard | |
| **3** | Breadth | 8–10 weeks | Network, API, monitoring, replay, imports | |
| **3a** | IoT & Device Security | — | Device exposure, then device vulnerability | |
| **4** | Intelligence | 6–8 weeks | Calibrated confidence, scores, reports, AI | |
| **5** | Depth tools | 10–14 weeks | Code, container, cloud, supply chain, LLM | |
| **6** | The site | 10–14 weeks | The product users actually log into | |
| **7** | Enterprise | ongoing | SSO, RBAC, residency, MSSP, mobile | |

Phases 0–5 are terminal-only. Nothing has a user interface until Phase 6. Realistically **18–24 months to a paid site**.

---

## What we claim

Everything in the tool catalogue can be copied by a competitor. These cannot be copied quickly, and they are the reason to build this rather than resell a scanner.

### 1. Proof, not verdicts

Every finding carries the raw evidence and a **control** — the paired negative that makes the observation mean something. *"The record was there"* is not evidence. *"The record was there and this made-up name was not"* is. Developers argue with scanners; they do not argue with a screenshot of their own server.

### 2. Confidence separate from severity, and five honest states

`confirmed` · `highly_likely` · `suspected` · `informational` · **`inconclusive`**

A 95%-confidence High is more urgent than a 40%-confidence Critical, so triage sorts by **severity × confidence**. And **returning `inconclusive` is a feature** — a blocked, rate-limited or ambiguous result is reported as "we could not tell", never as a guess. State is computed, never hand-set.

### 3. The deprecation clock — what breaks, and when *(v3.4)*

Every scanner says what is broken today. We also say what is fine today and **stops being fine on a date**: certificate lifetimes falling to 200, then 100, then 47 days on a published schedule. Deadlines are curated data with a primary source per entry and a review date, because a rotted clock asserts wrong dates in our name.

### 4. Prove, connect, close *(v3.4, [ADR-022](docs/02-decisions.md))*

- **Prove** — make the target's own infrastructure demonstrate the bug via an out-of-band callback. *We never guess; we make your server phone us.*
- **Connect** — compose related findings into one attack story, with confidence inherited from the weakest link. A finding that links three stories outranks an isolated one of equal severity.
- **Close** — re-run the exact test that proved a finding and close it **with evidence**, free. And only ever on a positive observation that the problem is gone: blocked, errored or inconclusive leaves it open.

### 5. Safe by construction — which becomes the product for devices *(v3.4, [ADR-021](docs/02-decisions.md))*

The IoT & Device Security Scanner's claim is not "we scan IoT" — many say that. It is that the scan is **safe to point at fragile equipment**: no credential testing, no writes, no state change. Existing tools are either passive and expensive or aggressive and dangerous. Our no-exploitation rule stops being a constraint and becomes the differentiator.

### Also new in v3.4

**Post-quantum exposure** and **AI / agent exposure** (MCP servers, agent panels, model endpoints — passive detection only). Both are *observation plus rule*, not new research capability.

---

## What we deliberately do not claim

Being clear about this is what keeps the rest credible.

| Cut | Why | Where |
|---|---|---|
| Attack-path / chokepoint analysis | Wiz and XM Cyber's core product. Phase 4 ships basic same-asset correlation and hand-written composition rules — not a graph engine. | [ADR-014](docs/02-decisions.md) |
| Reachability analysis | Endor Labs' entire product. Supply-chain scanning does direct-dependency matching and says so plainly. | [ADR-014](docs/02-decisions.md) |
| "Almost nobody does BOLA testing" | False since Dec 2025. Build the feature; never make the novelty claim. | [ADR-014](docs/02-decisions.md) |
| Nmap parity | naabu is port discovery only. Service fingerprinting is scoped to ~50 services. | [ADR-003](docs/02-decisions.md) |
| Exploitation of any kind | No shells, no state change, no data extraction, no brute-force, no load testing. | [ADR-004](docs/02-decisions.md) |

**And the 18-tool platform shape is not novel.** Plenty of vendors have that list. What we are betting on is the proof layer, not the catalogue.

---

## The four things that must not be compromised

1. **Every finding carries evidence and a confidence score.** Severity, confidence and state are three separate axes. This is the product.
2. **We never exploit.** Blind bugs are proven with out-of-band callbacks. *We prove the door is unlocked; we never walk in and rearrange the furniture.*
3. **Permissive open source, or we build it ourselves.** No Nmap, Nessus, Burp, or Semgrep rules — not even inside a container. We import their output instead, which turns a licence limit into a wedge.
4. **No active check without verified ownership**, enforced deny-by-default in code. Passivity is declared **per check**, not inferred from the mode name, and an undeclared check counts as active.

---

## How accuracy is proved

A scanner is not finished because it runs. It is finished when it hits **three numbers** — precision, recall, and an inconclusive rate under 15% — against targets whose correct answer we already know.

```
scanner   checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
email        240   21    0    0      1.000    1.000    0.0%     0.8%  PASS
tls          134    5    0    0      1.000    1.000    6.0%     0.0%  PASS
```

Two caveats we publish rather than bury:

- **A gate number is read with its claim count.** TLS's 1.000 rests on **5 claims out of 134 checks**. Honest, and thinner than it looks.
- **The corpus proves regression, not correctness.** A corpus written by the scanner's author encodes the scanner's assumptions. **Six real defects have survived corpora at precision 1.000** — every one found by a live run or by review, none by the corpus. Live verification is part of a tool's definition of done ([ADR-017](docs/02-decisions.md)).

---

## What is built, and what is not

**Built and passing:** Email Security (17 checks) · SSL/TLS Analyzer (14 checks) · the Scanner Contract · the confidence engine · ownership verification with an audit trail · record/replay for DNS, TLS and HTTP · the asset graph · the finding store and `scan verify` · the correlation pass · the deprecation calendar.

**Not built, stated plainly:** DNS enumeration and the Website Scanner (Tools 3 and 4, next) · the out-of-band callback server · every Phase 3+ tool · calibrated confidence (everything is `confidence_provisional: true` until Phase 4) · post-quantum detection, which needs Python 3.15 — measured, not assumed · the website itself.

---

## What to do next

**Tool 3 — DNS & Subdomain Enumeration.** It produces the asset list every other tool scans, and it is the first scanner that can discover assets onto the shared graph rather than read one seeded for it. Settle its recall definition before writing any of it: "all subdomains that exist" is not a knowable set, and publishing a corpus-relative number as though it were absolute is the specific dishonesty this product exists to avoid.

Then **Tool 4 — Website Scanner (Light)**, now unblocked by HTTP record/replay, and widened in v3.4 to include AI and agent exposure.

---

*Version 3.4 — 2026-08-28. Supersedes v3.1. The original v2 is preserved unedited at [docs/archive/](docs/archive/tools-and-features-list-v2.md).*
