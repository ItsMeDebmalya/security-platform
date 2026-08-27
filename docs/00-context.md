# 00 — Context

*What we are building, for whom, and the strategy we have chosen. Read this first.*

---

## The product

A security scanning platform. Users point it at assets they own — a domain, an IP range, an API, a repository, a cloud account — and get back findings that are **proven**, not guessed.

Reference point in the market: **armorist.ai** and similar "run a scan from the website" platforms. We are matching that shape of product (a menu of tools a user clicks and runs) and competing on one axis they do not: **every finding carries evidence and a calibrated confidence score.**

## Who it is for

| Segment | What they want | How they arrive |
|---|---|---|
| Solo developer / small startup | "Is my site obviously broken?" — free, instant, no signup | Free Light Scan, no account |
| Security engineer at a scale-up | A queue they can trust, with proof they can hand to a developer | Paid Pro / Business |
| Compliance owner | An evidence pack an auditor will accept | Business tier, reports |
| Agency / MSSP | Run scans for many clients, white-label the output | Business / Enterprise |

## The one-line strategy

> **We cover jobs, not tools.** A user does not need "Nmap." A user needs "tell me what ports are open." We do that job with tools whose licences allow commercial use, and with our own engines where accuracy matters.

---

## Our build strategy — tool-first, not platform-first

**This is the most important decision in this document set, and it is a change from the original v2 plan.**

The original plan built the platform (accounts, billing, dashboard) and the flagship Website Scanner in parallel over 4–5 months, aiming at a launch. We are not doing that.

**What we are doing instead:**

1. Build **one scanner at a time**, as a standalone command-line tool.
2. For each one, prove it produces **correct results** against a corpus of targets where we already know the right answer.
3. Only when a scanner passes its accuracy gate does it count as done.
4. Accumulate a shelf of proven scanners.
5. **Then** build the website and wrap the shelf in it.

**Why this is the right call for us:**

- Accuracy is the entire product thesis. If we build the UI first, we will spend months making a pretty wrapper around results we cannot vouch for.
- A scanner that runs from a terminal can be tested, diffed, and iterated on in seconds. The same scanner behind a web UI takes minutes per iteration.
- It defers every expensive decision (framework, hosting, payments, auth) until we actually know what the platform has to carry.
- We can stop at any point and still have something of value: working tools.

**The one risk, and how we handle it:**

Building tools in isolation usually produces a pile that does not fit together — different output shapes, different config, no shared idea of what a "finding" is. Wrapping that in a site later means rewriting most of it.

We avoid that by defining a **Scanner Contract** *before* tool #1 and never breaking it. It is small — a finding schema, a run interface, an evidence format. Any tool that satisfies the contract can be dropped into the platform later with no changes. That is Phase 0 — budgeted at 3–4 weeks. See [01-architecture.md](01-architecture.md).

**Trade-off we are accepting:** no revenue and no user feedback until the site exists — now **18–24 months** on the revised estimate, not 12–18. We are choosing depth of accuracy over speed to market. If that trade-off stops feeling right, see [07-open-questions.md](07-open-questions.md) — it is listed there as a decision to revisit, with the trigger conditions.

---

## What "correct results" means here

This is the standard every scanner is held to, and it is why the tool-first order works.

For each scanner we maintain a **ground-truth corpus**: targets where we know the true answer in advance.

- **Known-vulnerable targets** — deliberately broken apps we host or use (OWASP Juice Shop, DVWA, VAmPI, badssl.com, our own broken fixtures). We know exactly what should be found.
- **Known-good targets** — correctly configured assets we control. Anything reported here is a false positive.
- **Frozen real-world captures** — recorded responses from real sites, replayed offline so the test is deterministic and we are not re-scanning third parties.

A scanner ships when it hits its accuracy gate on that corpus — thresholds are per-tool and defined in [03-roadmap.md](03-roadmap.md). We measure **precision** (of what we reported, how much was real), **recall** (of what was really there, how much we caught), and **inconclusive rate**. Precision is weighted higher: a scanner that misses things is disappointing, a scanner that cries wolf is worthless.

**How those numbers are computed is not obvious** and is specified in [10-measurement.md](10-measurement.md) — a scanner emitting five states and a confidence score does not fit binary precision/recall without an explicit rule. In short: `confirmed` and `highly_likely` are the reported positives; `suspected` and `informational` are excluded and tracked separately; `inconclusive` is excluded from both sides **and capped**, so a scanner cannot score perfect precision by shrugging at everything.

The corpus also includes a **benchmark tier** — OWASP Benchmark and WAVSEP — because Juice Shop and DVWA alone carry only tens of planted vulnerabilities, which is too small a sample to compute a meaningful precision figure.

---

## The three scan modes (global, apply to every tool)

Every scanner exposes the same three modes. This is a product-wide contract, not a per-tool choice.

| | Light | Standard | Deep / Validated |
|---|---|---|---|
| **What** | Passive only — public data and normal responses | Active — we send test requests | Standard + we prove each finding |
| **Time** | 30s – 2min | 5 – 30 min | Longer, varies |
| **Permission** | None | **Verified asset ownership required** | Ownership + explicit authorisation agreement |
| **Risk to target** | Effectively zero | Low, rate-limited | Low, rate-limited |
| **Commercial role** | Free hook | The paid product | Business tier and above — the differentiator |

**Enforcement is not optional.** A Standard or Deep scan against an unverified asset must be impossible, not merely discouraged. See [06-guidelines.md](06-guidelines.md).

---

## What makes us different

**Revised in v3.1 after an adversarial review.** The first draft claimed five differentiators. Three did not survive contact with the market, and pretending otherwise is how a small team spends a year building the thing it is worst-placed to win. What is left is narrower and real.

### What we can actually own

1. **Evidence, not verdicts** — every finding shows the exact request, the exact response, the timing delta, the DNS answer, the cert chain. Developers argue with scanners; they do not argue with their own server returning 47 rows for `1=1` and 0 for `1=2`. Cheap relative to its value, and genuinely under-emphasised by competitors.
2. **Five honest result states, including `inconclusive`** — saying "we tried and could not determine" is a real differentiator because nobody else will admit it. Costs almost nothing to implement and buys disproportionate trust with experienced users.
3. **Confidence separate from severity** — "Critical, 96% confidence, confirmed by independent re-test." Triage sorts by *Risk × Confidence*. Honest here means *calibrated*, with real limits on what can be calibrated at our data volume — see [ADR-007](02-decisions.md#adr-007--confidence-is-separate-from-severity-and-calibrated).
4. **Close the loop** — after a fix, re-run the exact test that proved the problem and close it with evidence. Always free. Most tools only open problems.

### Added in v3.4 — what the calendar gives us

*[ADR-020](02-decisions.md#adr-020--amends-adr-014-what-we-claim-now-that-the-ground-has-moved) amends ADR-014. The three cut claims stay cut; these four were not checkable when it was written.*

5. **The deprecation clock** — we report what breaks **on a date**, not only what is broken today. *"Three of your certificates stop being reissuable on 15 March 2027."* Competitors report the present tense. This is a calendar applied to observations we already make, so it is cheap for us and legible to someone who does not read scanner output.
6. **Post-quantum exposure** — whether traffic sent today can be recorded now and decrypted once quantum hardware exists. Roughly half of domains are exposed and almost nothing tells them.
7. **Certificate lifetime readiness** — whether a renewal process survives 47-day certificates. Renewals go from about one a year to about eight by 2029; this affects everyone and nobody is warning them.
8. **AI and agent exposure** — exposed MCP servers, agent admin panels and unauthenticated model endpoints. A new surface, passively detectable, and not yet productised by anyone.

9. **A device scanner that is safe to run** — the IoT & Device Security Scanner ([ADR-021](02-decisions.md#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family)). Not "we scan IoT", which many claim. The claim is *safely*: no credential testing, no writes, no state change — and honest confidence in the noisiest corner of security scanning, where the industry norm is to print forty criticals from a banner match. Our no-exploitation rule stops being a constraint and becomes the product.

**These are worth little on their own.** A date nobody believes is just another alert. What makes them defensible is 1–4 above: the evidence, the honest `inconclusive`, the confidence that is separate from severity. The calendar is the pitch; the proof is why anyone should act on it.

### What we cut, and why

| Dropped claim | Why |
|---|---|
| **Attack path + chokepoint analysis — "the moat"** | It is Wiz's and XM Cyber's core product, built by funded research teams, and it needs an IAM/resource graph we would not have until Phase 5. Phase 4 ships basic same-asset correlation instead. |
| **Reachability analysis as the supply-chain differentiator** | This is Endor Labs' entire company. A single-language MVP is 3–6 months and would still be visibly worse. We ship direct-dependency matching and say plainly that we do not do reachability. |
| **"Almost nobody does BOLA testing properly"** | True around 2021–23, not now. StackHawk shipped multi-identity business-logic testing in Dec 2025; Escape and Akto already had it. We still build it — we just stop calling it novel. |

### On novelty generally

The "menu of 18 scanning tools in one platform" shape is **not novel and we should never claim it is**. Intruder.io, Detectify, Probely, Pentest-Tools.com and armorist.ai all occupy this space today, commercially live, funded, with years of tuning. Our bet is not a new category. It is doing a handful of tools with unusual rigour about proof and uncertainty. See [ADR-014](02-decisions.md#adr-014--descope-the-differentiation-claims-to-what-two-people-can-actually-own).

## What we deliberately do not do

We do not exploit. No reverse shells, no Metasploit-style exploitation, no credential brute-forcing or spraying, no data extraction, no DDoS or load testing, no phishing simulation, no endpoint agents.

Blind vulnerabilities are proven with **out-of-band callbacks and canary tokens** instead: we make the target request a unique URL only we control. If our server receives it, the bug is proven with certainty and nothing was touched.

> *We prove the door is unlocked. We never walk in and rearrange the furniture.*

Full list with reasoning: [02-decisions.md](02-decisions.md), ADR-004.

---

## Document map

| Doc | What is in it |
|---|---|
| **00-context.md** | This file. Product, strategy, standards. |
| [01-architecture.md](01-architecture.md) | The Scanner Contract, finding schema, how a scan runs, target architecture for the eventual site |
| [02-decisions.md](02-decisions.md) | ADRs — every decision with its reasoning and its reversal cost |
| [03-roadmap.md](03-roadmap.md) | Phase by phase, tool by tool, with accuracy gates and exit criteria |
| [04-phase-0-foundations.md](04-phase-0-foundations.md) | Task-level plan for the shared skeleton (the week before tool #1) |
| [05-phase-1-first-tools.md](05-phase-1-first-tools.md) | Task-level plan for the first four scanners |
| [06-guidelines.md](06-guidelines.md) | Engineering, safety, legal and licence rules that apply to all code |
| [07-open-questions.md](07-open-questions.md) | What is undecided, who decides, and by when |
| [08-changelog.md](08-changelog.md) | What changed from v2 and v3, what was deferred, **and how to revert** |
| [09-ownership-verification.md](09-ownership-verification.md) | The legal gate on every active scan — methods, lifecycle, audit record |
| [10-measurement.md](10-measurement.md) | How precision, recall and the gates are actually computed |
| [11-operations.md](11-operations.md) | Incident response, observability, secrets, data retention |
| [reference/product-spec.md](reference/product-spec.md) | Full catalogue of all 18 tools and 12 platform features — the surviving detail from v2 |
| [archive/tools-and-features-list-v2.md](archive/tools-and-features-list-v2.md) | The original v2 document, unchanged |
