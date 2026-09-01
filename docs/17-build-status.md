# 17 — Build Status: what exists, what is owed

*A status mirror of the original proposal, read in the same five parts. Version 3.4, as at 2026-09-01.*

**What this is.** [docs/archive/tools-and-features-list-v2.md](archive/tools-and-features-list-v2.md) is the wishlist: everything we said we would build, written before anything was built. This document is the same list with the truth written next to each row.

**How to read this** — the parts are the v2 parts, deliberately:

- **Part A** = the tools users click and run
- **Part B** = platform features that support the tools
- **Part C** = the features that make us different, not just equal
- **Part D** = priority table and phase plan
- **Part E** = things to decide before building

**Status vocabulary**, used consistently throughout. There are only four values, and *"partial"* is not one of them — a half-built thing is **not built** with a note saying which half exists.

| | Meaning |
|---|---|
| ✅ **built** | Exists, tested, and where it is a scanner, passing its accuracy gate |
| 🟡 **built, not proven** | Code exists and tests pass, but the claim it supports is not yet evidenced against the world |
| ⬜ **not built** | Planned. Nothing exists |
| ❌ **cut** | Deliberately not being built. The ADR that cut it is named |

**The one-line summary.** Of 18 tools in Part A, **two are built**. Of the platform features in Part B, the terminal-only subset is built and everything user-facing is not. The differentiators in Part C are the part that is furthest ahead — which is the whole strategy working as intended.

> **Read [14-progress-ledger.md](14-progress-ledger.md) before trusting any number here.** This document says *what* stands. The ledger says what broke on the way and what that cost. Where the two disagree, the ledger is right — it is append-only and this file is rewritten.

---

# PART A — THE TOOLS

## A-summary

| # | Tool | v2 phase | Real phase | Status |
|---|---|---|---|---|
| A7 | **Email Security Scanner** | 1 | 1 | ✅ **built — gate passing** |
| A3 | **SSL/TLS Analyzer** | 1 | 1 | ✅ **built — gate passing** |
| A4 | Domain & Subdomain Enumeration | 1 / 2 | 1 (tool 3) | ⬜ next |
| A1 | Website Scanner — Light | 1 | 1 (tool 4) | ⬜ |
| A1 | Website Scanner — Standard | 1 | 2 | ⬜ the hard one, 5–8 months |
| A2 | Network Scanner | 2 | 3 | ⬜ |
| A6 | API Scanner | 2 | 3 | ⬜ |
| A17 | Attack Surface Monitor | 2 | 3 | ⬜ |
| A5 | Deface Monitoring | 2 | 3 | ⬜ |
| — | **IoT & Device Security Scanner** | *not in v2* | 3a | ⬜ new in v3.4, [ADR-021](02-decisions.md) |
| A18 | Security Score & Reporting | 2 | 4 | ⬜ |
| A16 | Compliance Readiness | 3 | 4 | ⬜ |
| A15 | Third-Party / Vendor Risk | 3 | 4 | ⬜ reuses Light scanners |
| A14 | Credential Exposure Monitor | 3 | 4 | ⬜ blocked on legal — Q4a/Q6 |
| A9 | Supply Chain Scanner | 3 | 5 | ⬜ without reachability — [ADR-014](02-decisions.md) |
| A11 | Code Scanner (SAST + secrets) | 4 | 5 | ⬜ |
| A8 | Container Scanner | 4 | 5 | ⬜ |
| A10 | Cloud CSPM | 4 | 5 | ⬜ |
| A12 | AI / LLM Application Scanner | 4 | 5 | ⬜ passive AI-exposure detection pulled earlier |
| A13 | Mobile App Scanner | 5 | 7 | ⬜ |

**Two of twenty.** That ratio is the honest headline, and it is not behind schedule — [ADR-001](02-decisions.md) builds tools one at a time and gates each on accuracy before the next starts. A row moves from ⬜ to ✅ only by passing three numbers.

---

## A7 — Email Security Scanner ✅

**Gate:** precision ≥ 0.99, recall ≥ 0.95, inconclusive ≤ 15% · **Result:** 1.000 / 1.000 / 0.8% over 240 checks and 21 claims, 16-case corpus.
**Plus:** a live sweep of 50 real domains — 8 flagged, all hand-verified true positives, zero false positives.

**17 checks, all passive DNS.** 9 in Light, 8 more in Standard.

| Light | Standard |
|---|---|
| `spf-missing` · `spf-invalid` · `spf-multiple-records` · `spf-too-permissive` | `spf-lookup-limit` · `dmarc-pct-partial` · `dmarc-no-rua` · `dmarc-alignment` |
| `dmarc-missing` · `dmarc-invalid` · `dmarc-policy-none` | `dkim-missing` · `dkim-weak-key` |
| `mx-missing` · `spoofing-possible` | `mta-sts-missing` · `tls-rpt-missing` |

Built as **RFC parsers, not regexes** — SPF (7208), DMARC (7489), DKIM (6376), each pure and separately tested before anything touched DNS.

**What v2 asked for and we do not have:**

| v2 item | Status | Why |
|---|---|---|
| Open relay test | ⬜ **D4** | Needs an SMTP connection — active, not passive. Belongs behind the authorisation gate |
| Mail server TLS configuration | ⬜ **D4** | Same |
| Look-alike / typosquat domain detection | ⬜ **D5** | Needs RDAP over HTTP plus a permutation engine — larger than the rest of Tool 1 combined |
| Domain reputation / blacklist status | ⬜ | Needs a paid data API (Q8) |
| BIMI record check | ❌ **cut** | Its absence is a branding gap, not a security finding. Deliberately out of scope, not deferred |

**The decision worth knowing:** `dkim-missing` can never be a confident finding. Selectors are chosen freely by the sender and cannot be enumerated, so failing to guess one of 17 common names proves nothing. The check reaches a verdict only when it *finds* a key. This is the single most likely place for a competitor to ship a false positive.

---

## A3 — SSL/TLS Analyzer ✅

**Gate:** precision ≥ 0.98, recall ≥ 0.95, inconclusive ≤ 15% · **Result:** 1.000 / 1.000 / 0.0% over 134 checks and **5 claims**, 14-case corpus.
**Plus:** 67 facts cross-checked against `testssl.sh` across 6 servers with no disagreements, and live verification against six `badssl.com` subdomains.

**14 checks.** Our own TLS engine ([ADR-016](02-decisions.md)), not a `testssl.sh` wrapper — that reverses the phase plan, so it got an ADR.

`tls-cert-expired` · `tls-cert-expiring-soon` · `tls-cert-not-yet-valid` · `tls-cert-self-signed` · `tls-untrusted-root` · `tls-chain-incomplete` · `tls-hostname-mismatch` · `tls-weak-key` · `tls-weak-signature` · `tls-weak-cipher` · `tls-protocol-obsolete` · `tls-no-forward-secrecy` · `tls-no-certificate-transparency` · `tls-no-handshake`

**Read the gate number with its claim count.** Precision 1.000 rests on **5 claims, not 134 checks**. The rest surface as `suspected` because they rest on a single independence class — `expiring-soon` is arithmetic on one certificate field; `untrusted-root` and `chain-incomplete` are only knowable from path building. The measurement rules excuse hedged findings from both true positives and false negatives, so the number is not distorted. It is thinner than it looks.

**What v2 asked for and we do not have:**

| v2 item | Status | Why |
|---|---|---|
| HSTS presence and quality | ⬜ **D10** | It is an HTTP response header, so it needs an HTTPS GET. **Unblocked** by HTTP record/replay (0b.4) — owed only because nobody has written the checks yet |
| Overall A+–F grade | ⬜ **D9** | Deferred by decision. A grade is an opinion and opinions get argued with; *"expires in 5 days"* does not. Easy to add, hard to change once customers build expectations on it |
| Certificate revocation (OCSP / CRL) | ⬜ **D12** | `revoked.badssl.com` currently returns nothing, which reads as a pass. **A visible gap in a demo.** Also needs a ruling on whether calling the issuing CA counts as passive |
| Named CVEs — Heartbleed, POODLE, ROBOT | ⬜ | Each needs its own behavioural probe. None written |
| A positive case for `tls-weak-cipher` | ⬜ **D11** | RC4 and 3DES are compiled out of OpenSSL 3 — verified by trying to serve them, not assumed |

---

## The tools not yet started

Nothing below this line exists. Ordered as the roadmap orders them, with the one thing about each that is already decided.

**A4 · Domain & Subdomain Enumeration — next.** Feeds every other tool; it is the pipeline that produces the asset list. The mechanism it needs — the asset graph ([ADR-019](02-decisions.md)) — is already built, because deciding an output shape after writing the producer is the expensive order. Recall here is **corpus-relative, not absolute**: "all subdomains" is not a knowable set, and any published number must say so.

**A1 · Website Scanner.** Light is Phase 1; Standard is the whole of Phase 2 at **5–8 months**, re-estimated upward by roughly 3× after comparing how long ZAP, Nuclei and Burp took to reach acceptable quality on the same problems. Its scope was also cut.

**A2 · Network Scanner.** naabu, never Nmap — the licence bars inclusion *even inside a container*. Service fingerprinting is scoped to ~50 services with **no claim of Nmap parity** ([ADR-003](02-decisions.md)).

**A6 · API Scanner.** Real BOLA/BFLA testing needs multi-identity session handling and is worth building. The v2 novelty claim — *"almost nobody does BOLA testing"* — is ❌ **cut**: false since Dec 2025. Build the feature, never make the claim ([ADR-014](02-decisions.md)).

**A9 · Supply Chain Scanner.** Ships as direct-dependency matching. **Reachability analysis is ❌ cut** — it is Endor Labs' entire product. We say plainly that we do not do it.

**A10 · Cloud CSPM.** Narrow angle only: connect what we see outside to what we see inside. Not competing with Wiz on breadth.

**A12 · AI / LLM Scanner.** The full scanner is Phase 5, but **passive AI-exposure detection** — MCP servers, agent panels, model endpoints — was pulled forward into the v3.4 claims as observation-plus-rule, not new research capability.

**IoT & Device Security Scanner** *(new, not in v2)*. Its claim is not "we scan IoT" — many say that. It is that the scan is **safe to point at fragile equipment**. See [15-iot-scanner.md](15-iot-scanner.md); the safety rules there are stop-the-line. Owed first: **D14** (research the surface at all) and **D15** (a real device network — an emulator written from an RFC agrees with a scanner written from the same RFC).

---

# PART B — PLATFORM FEATURES

The dividing line: **everything terminal-facing is built; everything user-facing is Phase 6.** That is [ADR-012](02-decisions.md), not an accident of scheduling.

## What exists

| Area | Status | What actually landed |
|---|---|---|
| **The Scanner Contract** | ✅ | Frozen. `contracts/*.schema.json` (finding, evidence, scanresult, scanrun), `core/models.py`, `BaseScanner`, registry, `ScanContext` |
| **Core services** | ✅ | `authz` · `dns` · `http` · `tls` · `evidence` · `confidence` · `state` · `ratelimit` · `cost` · `killswitch` · `ids` |
| **The `scan` CLI** | ✅ | `list`, `run`, `verify`, `correlate` — with `--mode`, `--format`, `--record`/`--replay`, `--out`, `--store`, `--scope-file`, `--seed-assets`, `--fail-on`, real exit codes |
| **Corpus harness** | ✅ | `core/measurement.py` + `cli/corpus.py` — precision, recall, inconclusive rate, baseline comparison, CI regression failure |
| **Ownership verification** | ✅ | Deny-by-default in `core/authz.py` from tool #1, not Phase 6 ([ADR-015](02-decisions.md)). `scripts/authorise-domain.sh` polls the zone's own authoritative nameservers and writes the row only after seeing the nonce |
| **Kill switch + cost meter** | ✅ | Both from the first scan, per [ADR-004](02-decisions.md) and the cost rule |
| **Record / replay** | ✅ | Generic in `core/replay.py`, with DNS, TLS and HTTP backends (0b.3, 0b.4) |
| **The asset graph** | ✅ | `core/assetgraph.py` — scanners exchange assets through the run, never through each other ([ADR-019](02-decisions.md)) |
| **Finding store** | ✅ | `core/store.py` — SQLite, keyed `(id, org_id)`. Findings persist between scans; history survives re-scans |
| **`scan verify` — closing the loop** | ✅ | Re-runs the exact check that proved a finding. Closes **only** on a positive `clear`; blocked, errored or inconclusive leaves it open and says why |
| **Correlation pass** | ✅ | `core/correlation.py` + `config/composition_rules.yaml` — curated rules, not graph traversal. Two rules so far |
| **Deprecation calendar** | 🟡 | `core/deprecation_calendar.py` + `config/deprecation_calendar.yaml` — curated, sourced, review-dated. **The dates themselves are unverified — D13** |
| **Tool registry + licence check** | ✅ | `tools/registry.yaml`, `make licence-check`, enforced in CI |
| **Test targets** | ✅ | `docker-compose.yml` — Juice Shop, DVWA, VAmPI, badssl. `make targets-up` |

## What does not exist

Every one of these is Phase 6 or later by [ADR-012](02-decisions.md). Listing them is not a backlog; it is the reason the roadmap says 18–24 months.

**B1 accounts and onboarding · B2 scan scheduling and management UI · B3 findings management UI · B4 Request Replay · B5 Canary Token generator · B7 AI assistant · B8 reporting and PDFs · B9 alerts, integrations, ticketing, SIEM export · B10 learning content · B11 team and RBAC · B12 billing and credits.**

Two of these deserve a note because they are cheaper than they look:

- **B5 canary tokens** and the **out-of-band callback server** are the same infrastructure. We must build it anyway to prove blind bugs safely ([ADR-008](02-decisions.md)); exposing it as a user feature costs almost nothing extra. Still ⬜ — the OOB server is the first task of Phase 2.
- **B6 payload library** — `payloads/` exists as a directory and is empty. The format was meant to be established in Phase 1 even though Light modes send nothing. **Not done.**

**Not built and not on any list:** *importing findings from other scanners* ([ADR-010](02-decisions.md)) — Nessus `.nessus`, Nmap XML, Burp XML, SARIF, CycloneDX. This is the wedge that turns a licence limitation into a sales answer, it is mostly parsing work, and nothing exists yet.

---

# PART C — WHAT MAKES US DIFFERENT

**This is the part that is furthest ahead, and that is deliberate.** Two scanners with a proof layer beats twenty without one, because the catalogue is copyable and the proof layer is not.

| v2 claim | Status | Where it stands |
|---|---|---|
| **C1 · Confidence separate from severity** | 🟡 | The engine is built and enforced — a `Finding` whose stored confidence or state disagrees with `core/state.py` is **rejected outright**. But confidence is **provisional until Phase 4 calibration**, and calibrates per (scanner × detection_method), never per check. Today "0.9" is a considered prior, not a measured frequency |
| **C2 · Evidence shown, not just verdicts** | ✅ | Every finding carries a **control-vs-test pair**. *"The server errored"* is not evidence. In the TLS engine the pair falls out of the design rather than being reconstructed: two contexts do opposite jobs, and running both against one server *is* the control |
| **C3 · Five honest states** | ✅ | `confirmed` · `highly_likely` · `suspected` · `informational` · `inconclusive`. State is **computed by `core/state.py`, never hand-set**. `confirmed` requires validation to have run and passed. Measured inconclusive rates: email 0.8%, TLS 0.0% |
| **C4 · Attack path + chokepoint analysis** | ❌ **cut** | [ADR-014](02-decisions.md). Wiz and XM Cyber's core product, and it depended on Phase 5 data from Phase 4. What shipped instead: same-asset correlation with **curated composition rules** — the boundary stays exactly where the ADR drew it |
| **C5 · Close the loop, verify the fix** | ✅ | `scan verify`. Re-runs the exact test, closes with evidence, free. The strictness is the point: it closes only on a positive observation that the problem is gone |

## The claims added in v3.4

All four are *observation plus rule*, not new research capability — which is what makes them affordable for two people.

| Claim | Status | Blocker |
|---|---|---|
| **The deprecation clock** — what breaks on a date, not just what is broken | 🟡 | Mechanism built (`materialises_at`, dated findings, the curated calendar). **The dates are from vendor blogs and secondary summaries — D13.** A clock citing a wrong date is worse than no clock |
| **Certificate lifetime readiness** — 200 → 100 → 47 days | 🟡 | Same. Rides on the same calendar |
| **Post-quantum exposure** | ⬜ **D16** | Hard-blocked on **Python 3.15 final**. Reading back a negotiated key-exchange group needs `set_groups`/`get_groups`/`SSLSocket.group()`, which arrive in 3.15, not 3.13 as the roadmap originally claimed. Verified directly across 3.12–3.15rc1 |
| **AI and agent exposure** — MCP servers, agent panels, model endpoints, passive only | ⬜ | Unblocked by HTTP record/replay (0b.4). Not started |
| **Safe by construction** *(IoT, [ADR-021](02-decisions.md))* | ⬜ | The no-exploitation rule stops being a constraint and becomes the differentiator. Needs D14 and D15 first |

## What we deliberately do not do

Having a clear answer here makes us look deliberate rather than incomplete. Unchanged from v2 and reinforced by [ADR-004](02-decisions.md): **no exploitation, ever.** No shells, no state changes, no data extraction, no brute-force, no load testing.

> *We prove the door is unlocked. We never walk in and rearrange the furniture.*

Blind bugs are proven with out-of-band callbacks and canary tokens — aggressive proof, never intervention. **Prove, connect, close** ([ADR-022](02-decisions.md)) is entirely within that line: make the target's own infrastructure demonstrate the bug, compose findings into one story, then re-run the exact test to close it.

Also excluded, each for its own reason: Metasploit-style exploitation and password spraying (safety), DDoS and load testing (destructive by definition), BAS and EDR agents (different product), phishing simulation (involves real employees and a separate consent framework), SIEM and log monitoring (we integrate instead).

---

# PART D — WHERE WE ACTUALLY ARE

## D1 · The phase plan, with status

| Phase | Name | Rough time | Status |
|---|---|---|---|
| **0** | Foundations | 3–4 weeks | ✅ **complete** |
| **0b** | Foundation for the calendar — dates, asset graph, replay, verify, correlation | — | ✅ **complete** (0b.1–0b.9) |
| **1** | The cheap accurate tools | 4–6 weeks | 🟡 **2 of 4** — Email ✅, TLS ✅, DNS enum ⬜, Web Light ⬜ |
| **2** | The hard one — OOB server + Website Standard | 5–8 months | ⬜ |
| **3** | Breadth — network, API, monitoring, replay, imports | 8–10 weeks | ⬜ |
| **3a** | IoT & device security | — | ⬜ |
| **4** | Intelligence — calibration, scores, reports, AI | 6–8 weeks | ⬜ |
| **5** | Depth — code, container, cloud, supply chain, LLM | 10–14 weeks | ⬜ |
| **6** | **The site** — the product users log into | 10–14 weeks | ⬜ |
| **7** | Enterprise — SSO, RBAC, residency, MSSP, mobile | ongoing | ⬜ |

**Phases 0–5 are terminal-only. Nothing has a user interface until Phase 6.** Realistically **18–24 months to a paid site** — revised upward from 12–18 in v3.1 after Phase 0 and Phase 2 were both found to be materially underestimated.

**The ordering principle** is cheapest-and-most-deterministic first. Email and TLS were not chosen because they are exciting; they were chosen because if we cannot reach 99% precision on pure DNS, nothing harder will work.

## D2 · The deferred register — what is owed

Single source of truth is [14-progress-ledger.md §D](14-progress-ledger.md). **They cluster, and the clusters matter more than the individual rows.**

**Corpus realism — the gap between a gate number and a claim about the world**

| # | Item | Blocks |
|---|---|---|
| **D6** | ~50 real domains as a frozen corpus tier | Confidence in the published number. The 16 committed cases are synthetic zones *we wrote* |
| **D3** | Benchmark tier (OWASP Benchmark, WAVSEP) | Phase 2 web scanner |
| **D11** | A positive `tls-weak-cipher` case | Nothing; TLS gates without it |

**Capability gaps a user would notice**

| # | Item | Blocks |
|---|---|---|
| **D12** | Certificate revocation checking | Nothing formally — but `revoked.badssl.com` reads as a pass, and that is **visible in a demo** |
| **D4** | `open-relay`, `mail-tls-weak` | Nothing; Email gates without them |
| **D5** | `lookalike-domain` | Nothing |
| **D10** | HSTS checks | Nothing. **Unblocked** — just unwritten |
| **D9** | The A+–F TLS grade | Nothing. Deferred by decision, not by cost |

**Infrastructure**

| # | Item | Blocks |
|---|---|---|
| **D1** | **Verify CI actually runs** | Nothing yet — *but every gate claim rests on it.* A remote exists; no run has been observed |
| **D7** | CoreDNS container serving a local authoritative zone (`sptest.test`) | Standard-mode live testing, and a better Tool 1 corpus. ~1 hour of work |
| **D8** | `evidence_file` existence check in `core/authz.py` | Nothing; belt-and-braces |

**Unverified numbers in decision documents — the same failure mode twice**

| # | Item | Blocks |
|---|---|---|
| **D13** | Verify the v3.4 research numbers against primary sources | **Any external use of the numbers.** Certificate-lifetime dates, PQ adoption percentages and MCP exposure counts all came from vendor blogs |
| **D16** | Post-quantum needs Python **3.15**, not 3.13 | The post-quantum claim in [ADR-020](02-decisions.md) |

Both are a figure reaching an ADR or a roadmap row without being checked against its primary source. D16 was caught by measuring; D13 has not been caught yet, only suspected.

**New surfaces, unresearched**

| # | Item | Blocks |
|---|---|---|
| **D14** | Research IoT/device security as a candidate surface | Nothing yet. Left out of v3.4 *because it was not researched* — padding a plan with an unexamined surface is how the v3 differentiators got inflated |
| **D15** | A real device network to verify against | Calling tool 5a/5b done |

## D3 · The defects worth carrying forward

The ledger's most valuable section is *Found & fixed*, because a bug found once and forgotten is a bug found twice. Four that apply to **every** tool, not just the one that produced them:

1. **A corpus written by the scanner's author encodes the scanner's assumptions.** Six real defects survived corpora sitting at precision 1.000. Run against real targets and hand-verify before calling anything done ([ADR-017](02-decisions.md)).
2. **A tool with the same blind spot as the thing it verifies confirms nothing.** A correctly configured TLS client cannot handshake with the obsolete servers we are paid to find — and `openssl s_client` has the same safety floor, so it "disproved" a correct finding.
3. **Never put words in a target's mouth.** A finding once asserted a domain's SPF record was `v=spf1 -all` when it authorised nine IP ranges. Descriptions now quote what was *read*, never a reconstructed string.
4. **Ground truth that is wrong produces a green gate and a scanner nobody should trust.** Three separate faults in the TLS lab made every case silently the same case.

---

# PART E — WHAT STILL NEEDS DECIDING

Open questions live in [07-open-questions.md](07-open-questions.md). 🔴 blocks work now; 🟡 needs an answer before its phase; 🟢 can wait.

## Blocking

| # | Question | Why it blocks |
|---|---|---|
| 🔴 **Q4** | Legal review of the tool list | Needed before anything ships publicly. One review covering every approved licence, recorded in the tool registry |
| 🔴 **Q4a** | GDPR and third-party data | Blocks Phase 3. OSINT harvesting and vendor-risk scanning both touch personal data |
| 🔴 **Q5** | Terms of service and the authorisation agreement | Deep/Validated mode cannot be offered without it |

## Needed before their phase

| # | Question |
|---|---|
| 🟡 **Q1** | **When do we stop building tools and build the site?** |
| 🟡 **Q2** | **Do we validate demand before Phase 6?** |
| 🟡 Q4b | Legal exposure beyond licensing |
| 🟡 Q6 | Breach / credential data provider (gates A14) |
| 🟡 Q7b | Build or self-host the OOB server (gates all of Phase 2) |
| 🟡 Q7c | The attack-path data model |
| 🟡 Q8 | Paid data API budget — Censys/SecurityTrails, VirusTotal |
| 🟡 Q9 | AI provider and cost model |
| 🟡 Q10 | Where do the scanners run? |
| 🟡 Q13 | Does the free Light Scan need no signup at all? |
| 🟡 Q13b | Verified-tool status |

**Q1 and Q2 are the two that matter most right now**, and they are the same question asked twice: we have two proven tools, no users, and a roadmap that says nobody sees them for 18 months. Nothing in this document answers that — it is a decision, not a finding.

## Answered, recorded so they are not re-litigated

- **Q12b ✅** — build our own TLS engine, keep `testssl.sh` as a cross-check ([ADR-016](02-decisions.md)).
- **The licence rule ✅** — permissive OSS may be embedded; commercial, restrictive or unclear may not. Zero commercial tool licences in the scanning path. GPL tools run as separate processes only, and that applies to **data** as well as code: Wappalyzer's fingerprint database is GPL-3.0 and must not seed ours.
- **Ownership verification ✅** — exists from tool #1, deny-by-default in code, not deferred to Phase 6 ([ADR-015](02-decisions.md)).

---

## The shortest honest summary

**What we have:** a frozen contract, a working harness, two scanners that pass three numbers each, and a proof layer that most of the market does not have at all.

**What we do not have:** eighteen of twenty tools, any user interface, a single paying user, a verified CI run, or corpus evidence drawn from anything but zones we wrote ourselves.

**What that means:** the differentiator is real and the catalogue is not. Both statements need saying in the same breath, because either one alone is misleading.

---

*Companion to [tools-and-features-list.md](../tools-and-features-list.md) (the plan) and [14-progress-ledger.md](14-progress-ledger.md) (what happened). Update this file when a status changes; append to the ledger when a phase or tool closes.*
