# Security Platform — Build Plan

### Version 3.1 — restructured from a proposal into an executable plan, then validated against primary sources

**What this is:** a security scanning platform. Users point it at assets they own and get findings that are **proven**, not guessed. Market reference point: armorist.ai and similar.

**What changed in v3:** v2 was a good proposal — a list of tools and a priority table. It was not something you could build from. v3 turns it into a plan: a shared contract every scanner satisfies, an accuracy standard every scanner is held to, phase-by-phase task lists, and a record of every decision with its reasoning.

**The strategy, in one line:** build and prove scanners one at a time from the command line, then wrap the proven shelf in a website. Not the other way around.

---

## Start here

| Read this | If you want |
|---|---|
| **[docs/00-context.md](docs/00-context.md)** | The product, the strategy, and the standard everything is held to. **Read first.** |
| **[docs/01-architecture.md](docs/01-architecture.md)** | The Scanner Contract, the finding model, evidence, confidence, how it becomes a platform |
| **[docs/02-decisions.md](docs/02-decisions.md)** | Every decision, its reasoning, and what it costs to reverse |
| **[docs/03-roadmap.md](docs/03-roadmap.md)** | Phase by phase, tool by tool, with accuracy gates |
| **[docs/04-phase-0-foundations.md](docs/04-phase-0-foundations.md)** | The task list to start on today |
| **[docs/05-phase-1-first-tools.md](docs/05-phase-1-first-tools.md)** | The task list for the first four scanners |
| **[docs/06-guidelines.md](docs/06-guidelines.md)** | Rules for all code — safety, legal, accuracy, licences |
| **[docs/07-open-questions.md](docs/07-open-questions.md)** | What is still undecided, and by when it must be |
| **[docs/08-changelog.md](docs/08-changelog.md)** | What changed from v2 and v3, what was deferred, **and how to revert** |
| **[docs/09-ownership-verification.md](docs/09-ownership-verification.md)** | The legal gate on every active scan |
| **[docs/10-measurement.md](docs/10-measurement.md)** | How the accuracy gates are actually computed |
| **[docs/11-operations.md](docs/11-operations.md)** | Incident response, observability, secrets, retention |
| **[docs/reference/product-spec.md](docs/reference/product-spec.md)** | The full catalogue of all 18 tools and 12 platform features |
| **[docs/archive/tools-and-features-list-v2.md](docs/archive/tools-and-features-list-v2.md)** | The original v2 document, unchanged |

---

## The plan at a glance

| Phase | Name | Rough time | Ends with |
|---|---|---|---|
| **0** | Foundations | 3–4 weeks | A skeleton that runs a trivial scanner end to end |
| **1** | The cheap accurate tools | 4–6 weeks | Email, TLS, DNS enum, Web Light — each passing its accuracy gate |
| **2** | The hard one | 5–8 months | OOB callback server + Website Scanner Standard (descoped) |
| **3** | Breadth | 8–10 weeks | Network, API, monitoring, replay, imports |
| **4** | Intelligence | 6–8 weeks | Calibrated confidence, basic correlation, scores, reports, AI |
| **5** | Depth tools | 10–14 weeks | Code, container, cloud, supply chain, LLM |
| **6** | The site | 10–14 weeks | The product users actually log into |
| **7** | Enterprise | ongoing | SSO, RBAC, residency, MSSP, mobile |

Phases 0–5 are terminal-only. Nothing has a user interface until Phase 6. Realistically **18–24 months to a paid site**.

> **What v3.1 changed.** Three adversarial reviews checked v3 against primary sources. The Finding schema was found **unsafe to freeze** and has been fixed; Phase 2 was underestimated by ~3x and is now descoped; three claimed differentiators were cut as things a two-person team cannot own against funded incumbents; MobSF turned out to be GPLv3; and three missing planning areas (ownership verification, measurement, operations) became new documents. Full detail: [docs/08-changelog.md](docs/08-changelog.md).

---

## The four things that must not be compromised

1. **Every finding carries evidence and a confidence score.** Severity, confidence and state are three separate axes. Triage sorts by *Risk × Confidence*. This is the product — and, post-validation, most of what we can realistically claim as differentiation.
2. **We never exploit.** No shells, no state changes, no data extraction. Blind bugs are proven with out-of-band callbacks. *We prove the door is unlocked; we never walk in and rearrange the furniture.*
3. **Permissive open source, or we build it ourselves.** No Nmap, no Nessus, no Burp, no Semgrep rules — not even inside a container. We import their output instead, which turns a licence limitation into a wedge.
4. **No active scan without verified ownership.** A legal requirement, enforced in code, deny-by-default.

---

## What to do next

Start at [docs/04-phase-0-foundations.md](docs/04-phase-0-foundations.md), task 0.1. The first commit is `git init` — this repository is not yet under version control.

The single most important task in that list is **0.2, the Scanner Contract**. It is the one thing that makes "build tools one at a time" work instead of producing a pile that has to be rewritten when the site arrives. Do not start tool #1 before it is frozen.

---

*Version 3.1 — 2026-08-22. Supersedes v2, which is preserved in full at [docs/archive/](docs/archive/tools-and-features-list-v2.md).*
