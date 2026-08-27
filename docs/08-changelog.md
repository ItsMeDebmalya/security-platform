# 08 — Changelog and Revert Notes

*What changed from v2 to v3, why, what was deferred, and exactly how to go back if any of it turns out to be wrong.*

---

## The original is preserved

**[archive/tools-and-features-list-v2.md](archive/tools-and-features-list-v2.md)** — the v2 document, byte-for-byte unchanged.

Nothing was deleted. Every tool description, feature list, differentiator and decision from v2 survives, either in the working documents or in [reference/product-spec.md](reference/product-spec.md).

**To revert entirely:**
```bash
cp docs/archive/tools-and-features-list-v2.md tools-and-features-list.md
rm -rf docs/0*.md docs/reference
```
That returns you to exactly the state before this rewrite.

---

## What v3 changed

### 1. Build order: platform-first → tool-first

**v2:** Website Scanner and the platform (accounts, tiers, credits, AI assistant) built in parallel over 4–5 months to a launch.

**v3:** scanners built one at a time as CLI tools, each gated on accuracy; the site comes in Phase 6.

**Why:** founder's stated preference, and it matches the product thesis — accuracy is the differentiator, and accuracy is far cheaper to iterate on from a terminal.

**Reversal:** low cost. The Scanner Contract exists so the platform can be built at any point without touching scanners. To revert, start Phase 6 early and run it in parallel with tool work.

---

### 2. Added: Phase 0 and the Scanner Contract

**v2:** no shared foundation. Tools were described individually with no common output shape.

**v3:** a frozen contract — finding schema, evidence format, `BaseScanner`, `ScanContext` — plus core services and a corpus harness, all before tool #1.

**Why:** this is the entire mitigation for tool-first's failure mode. Without it, building tools one at a time produces a pile that has to be rewritten when the site arrives.

**Reversal:** do not. If tool-first is abandoned the contract is still correct and still needed.

---

### 3. Added: ground-truth corpus and accuracy gates

**v2:** "validation step that re-tests it before we show it" — a mechanism, but no measurement.

**v3:** every scanner has a corpus of known-answer targets and a precision/recall gate it must pass in CI before it counts as done.

**Why:** this is the concrete form of "check verify is that giving exact results how we want." Without ground truth there is no way to know a scanner works, no way to calibrate confidence, and no way to tell whether a change helped or hurt.

**Reversal:** none recommended. Abandoning it forfeits the product thesis.

---

### 4. Reordered: Website Scanner moved from first to fifth

**v2:** priority 1, built first.

**v3:** Phase 2, after Email, TLS, DNS enumeration and Web Light.

**Why:** it is the hardest tool to get right and the hardest to verify. Building it first means debugging the harness and the hardest detection logic simultaneously. Email and TLS are deterministic — if precision is poor there, the problem is provably the harness.

**Reversal:** moderate cost. You would be building the flagship without a proven harness. If time-to-market becomes the priority (see [Q1](07-open-questions.md#q1---when-do-we-stop-building-tools-and-build-the-site)), the cheaper move is to jump to Phase 6 with the Phase 1 tools, not to reorder Phase 2.

---

### 5. Split: the confidence engine

**v2:** priority 6, one item, in Phase 1.

**v3:** split across three phases — schema in Phase 0, provisional hand-assigned priors in Phase 1, **calibration in Phase 4**.

**Why:** calibration requires labelled outcomes, and labels require scans to have happened. "Confidence 96%" is only meaningful once verified against real outcomes; shipping uncalibrated numbers that look precise is worse than shipping none.

**Reversal:** none needed — the capability is not reduced, only correctly sequenced.

---

### 6. Moved later: OOB callback server relative to Standard web scanning

**v2:** priority 7, after the Website Scanner at priority 1.

**v3:** Phase 2a, explicitly **before** Standard web scanning.

**Why:** blind SSRF, blind SQLi and XXE cannot be proven without it, and exploitation is ruled out. Building Standard mode first means an entire class of findings stuck at `suspected` — on exactly the vulnerabilities that matter most.

---

### 7. Moved later: AI assistant, tiers, credits

**v2:** priorities 8 and 9, both Phase 1.

**v3:** Phase 4 and Phase 6.

**Why:** the AI assistant explains findings, and there are no findings with evidence until Phase 2 completes. Tiers and credits require a site to sell from.

**Reversal:** low cost either way; both are additive.

---

### 8. Changed: the timeline

**v2:** ~4–5 months to launch, ~21 months across all five phases.

**v3:** realistically 12–18 months to a paid site.

**Why:** the v2 estimate treated the platform as the launch. Accuracy-gated tools take longer per tool and produce a materially better product. This is a real cost of the strategy and it should be visible, not buried.

**This is the number to challenge if the strategy is questioned.** It is the honest price of tool-first.

---

### 9. Added throughout: implementation detail that did not exist in v2

Present in v3, absent in v2:
- Repository layout and module boundaries
- Finding schema with deterministic IDs and deduplication
- Evidence format with mandatory control-vs-test pairing and capture-time redaction
- The confidence calculation (log-odds combination, then calibration)
- Rate limiting, backoff, kill switch and scope enforcement as `core/` services rather than per-tool concerns
- Per-tool gotchas — SPF's 10-lookup rule, wildcard DNS, soft-404s, CDN header interference, backported versions
- CI enforcement of the licence and GPL-isolation rules
- Pre-merge checklist

---

## Deferred, with reasons

Nothing is dropped. These are scheduled later than v2 implied.

| Item | v2 | v3 | Why |
|---|---|---|---|
| Accounts, onboarding, teams | Phase 1 | Phase 6 | Undifferentiated; consumes time better spent on accuracy |
| Billing, tiers, credits | Phase 1 | Phase 6 | No site to sell from |
| AI assistant | Phase 1 | Phase 4 | Nothing to explain yet |
| Reporting / PDF export | Phase 2 | Phase 4 | Needs findings with evidence first |
| Security score | Phase 2 | Phase 4 | Needs multiple tools' findings to score across |
| Learning content | Phase 2 | Phase 4 | Cheap, additive, no dependency pressure |
| Integrations (Jira, Slack, SIEM) | Phase 2 | Phase 6 | Needs the platform |
| SSO, RBAC, residency | Phase 5 | Phase 7 | Unchanged in substance |
| Mobile scanner | Phase 5 | Phase 7 | Narrowest audience, highest effort |

---

## Preserved but relocated

| Content | Now lives in |
|---|---|
| Full descriptions of all 18 tools (A1–A18) | [reference/product-spec.md](reference/product-spec.md) |
| All 12 platform features (B1–B12) | [reference/product-spec.md](reference/product-spec.md) |
| The five differentiators (C1–C5) | [00-context.md](00-context.md), and as design requirements in [01-architecture.md](01-architecture.md) |
| Deliberate exclusions (Part C2) | [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) |
| Approved / forbidden tool tables (E2, E3) | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| Our own engines list (E4) | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) and [01-architecture.md](01-architecture.md) |
| Import feature rationale (E5) | [ADR-010](02-decisions.md#adr-010--import-findings-from-the-tools-we-cannot-embed) |
| Cost / margin reasoning (E6) | [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| Sign-off items (E7) | [07-open-questions.md](07-open-questions.md) |
| Safety and legal must-haves (E8) | [06-guidelines.md](06-guidelines.md), and as Phase 0 tasks |

---

## Things v2 mentioned that still need attention

Flagged so they are not lost in the reorganisation.

- **Companion document "Tool Coverage Matrix"** — referenced by v2, not present in this repository. Find it or recreate it; it held the full tool-by-tool competitor mapping.
- **Container scanner noise** — v2 correctly warned that one base image yields 500+ CVEs and that reachability filtering is mandatory or the tool is worthless. Carried into [03-roadmap.md](03-roadmap.md) Phase 5; do not let it be forgotten at build time.
- **Nmap inside a container is still a licence violation** — the specific trap most teams miss. Repeated in [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) and [06-guidelines.md](06-guidelines.md).
- **Published scanner IP ranges** — an E8 must-have, easy to defer forever. In [06-guidelines.md](06-guidelines.md); needs doing before Phase 2 volume scanning.
- **The labelled false-positive dataset** — v2 identified it as our most valuable asset. It only accumulates if collection is designed in from the start, which is why finding-to-method traceability is a Phase 0 contract requirement.

---

## v3.1 — validation pass (2026-08-22)

Three independent adversarial reviews checked the v3 plan against primary sources: tooling and licences, engineering feasibility versus prior art, and internal consistency. **The headline outcome: the Finding schema was found unsafe to freeze, and Phase 2 was underestimated by roughly 3x.** Nothing below was a v2 problem — these are corrections to v3.

### Blocking fixes to the Scanner Contract

Found before any code was written, which is the entire point of having frozen it late.

| Gap | Fix |
|---|---|
| No `ScanRun` entity and no `status` field, despite Phase 6 promising false-positive marking, accept-risk with expiry, and status history | Added `ScanRun` (id, target, mode, outcome, authz_ref, cost) plus `status`, `status_history`, `first_seen_scan_id`, `last_seen_scan_id` on Finding |
| ID formula collided on multi-instance and location-less findings, and broke history on `check_id` renames | Added `instance_key` discriminator, reserved `location: "$"` for target-level findings, added `renamed_from[]` |
| `state` documented as derived from confidence *and* "how we got there" — an ambiguity no code can resolve | Replaced with an explicit truth table in `core/state.py`. State is computed, never hand-set. `confirmed` now requires validation to have actually run and passed |
| Single scalar `detection_method`, though ADR-007 warns method independence must be tracked | Replaced with `detection_methods[]` carrying likelihood ratios and `independence_class` |
| Evidence schema was `http_pair`-shaped only; `oob_callback` and `timing` do not fit that shape | Added kind-specific sub-shapes, including sample arrays and a statistical test for timing |
| Attack-path model asserted as already solved by `location` + `target` | **That claim was wrong.** Added `related_assets[]` as a hedge and moved the real data model to an open question, to be validated by end of Phase 3 |
| No rule separating a scan error from an `inconclusive` finding | Written explicitly; added as a fifth Phase 0 acceptance test |

### Factual corrections

| Claim | Reality |
|---|---|
| MobSF listed as "open source" in the approved table | **GPLv3.** Also a Django app, not a CLI binary — must run as its own containerised service, never imported. It was the one GPL tool the GPL-handling section forgot to name |
| "Build our own Wappalyzer-style fingerprint DB" | Correct as an *approach*, but Wappalyzer's pre-2023 data and its forks are **GPL-3.0** and widely mirrored. Added an explicit guardrail against bootstrapping from them |
| ADR-008 rejected "Interactsh-style" OOB solutions | Conflated the **public instance** with self-hosting. Interactsh is MIT and self-hostable, covering all four protocols. Reopened as build-vs-adopt |
| naabu presented as an Nmap replacement | naabu is port discovery **only**. Nmap's service-probe database is ~12k signatures over 20 years. Scoped our fingerprinting honestly to ~50 services, no parity claim |
| Nmap licence claim | **Confirmed correct**, including the container case. Added the operative NPSL citation |
| Semgrep Dec 2024 rule licence change; Opengrep as the fork | **Confirmed correct.** Opengrep is healthier than claimed — LGPL-2.1, ~10-company consortium, actively developed |
| garak, PyRIT, Amass, and the Apache-2.0 tools | **Not verified.** Now marked `[UNVERIFIED]` in ADR-003 rather than left looking settled |

### Feasibility corrections

| Item | Was | Now |
|---|---|---|
| Phase 2 (Website Scanner) | 8–12 weeks, seven injection classes | **5–8 months**, descoped: DOM XSS and stored XSS deferred to Phase 2.5. Start from ZAP's crawler rather than building Playwright orchestration from scratch |
| Phase 0 | 1–2 weeks | **3–4 weeks**, with three implementer decisions now made in the doc |
| Total to a paid site | 12–18 months | **18–24 months** |
| Chokepoint analysis ("the moat") | Phase 4 differentiator | **Cut.** Wiz/XM Cyber's core product, and it secretly depended on Phase 5's CSPM graph. Phase 4 ships basic same-asset correlation |
| Reachability analysis | Phase 5 differentiator | **Cut.** Endor Labs' entire product. Direct-dependency matching only, stated plainly |
| BOLA multi-identity testing | "Almost nobody does it properly" | Feature kept, **claim killed** — StackHawk shipped it Dec 2025; Escape and Akto had it earlier |
| Confidence calibration | Per scanner, implied per-check precision | Per **(scanner × detection_method)**, ≥30 labels before a fitted curve replaces a prior. Below that the prior stands, possibly permanently, and the UI must say so |
| Live secret validation | "A small feature with big impact" | An **integration programme**. Scoped to 15–20 providers, permanently ongoing, per-provider ToS review required |
| Accuracy corpus | Juice Shop, DVWA, VAmPI, badssl.com | Added a **benchmark tier: OWASP Benchmark + WAVSEP.** The original corpus has tens of planted bugs and no negative population — too small for a meaningful precision figure |

### Gaps filled with new documents

- **[09-ownership-verification.md](09-ownership-verification.md)** — the legal gate was referred to by four documents and specified by none. Also closes a real hole: every method previously listed proves *domain* ownership, and none work for **IP/CIDR targets**, which the Network Scanner treats as first-class.
- **[10-measurement.md](10-measurement.md)** — precision/recall were undefined for five-state, confidence-scored output. Also closes the exploit where a scanner returning `inconclusive` for everything scores perfect precision.
- **[11-operations.md](11-operations.md)** — incident response, observability, our own secrets, and data retention were entirely absent.

### New ADRs

**013** measurement spec · **014** descope the moat claims · **015** ownership verification from tool #1

### What survived unchanged

The tool-first strategy (ADR-001), the Scanner Contract as a *concept* (ADR-002), the licence rule (ADR-003), no-exploitation (ADR-004), the corpus-gate discipline (ADR-006), and the Phase 1 tool ordering. The reviews were explicit that the contract-first approach is the right structural call for a small team — it is what surfaced these problems before they cost anything.

### Reverting v3.1

Every change above is additive or a correction to v3, and v3 itself is recoverable from git history. The three new documents can be deleted independently. **Do not revert the Finding schema changes** — they were made specifically to avoid a migration later, which is the expensive direction.

---

## Version history

| Version | Date | Change |
|---|---|---|
| v1 | — | Original tool list (not in this repository) |
| v2 | — | Added historical URL mining, OSINT harvesting, Request Replay, canary tokens, payload library; added deliberate exclusions; added Part E tooling decisions |
| **v3** | 2026-08-21 | Restructured from a proposal into a build plan. Tool-first strategy, Scanner Contract, accuracy gates, ADRs, phase plans, guidelines, open questions. Split into `docs/`. |
| **v3.1** | 2026-08-22 | Validation pass. Contract fixed before freezing; licence errors corrected; Phase 0 and 2 re-estimated; three differentiator claims cut; ownership-verification, measurement and operations docs added. |

---

## v3.2 — implementation additions to the frozen contract (Phase 0)

*Recorded here because [ADR-002](02-decisions.md#adr-002--freeze-the-scanner-contract-before-writing-tool-1) makes a contract change a migration rather than an edit. All three are **additive** — no existing field changed meaning, no stored finding needs rewriting — but they are changes to a document that says it is frozen, and burying them in a commit message would defeat the point of freezing it.*

### 1. `no_verdict_reason` on the Finding

**What:** a nullable enum on the finding — `timeout`, `servfail`, `waf_block`, `blocked_prerequisite`, `oob_unavailable`, `ambiguous_response`, `rate_limited`.

**Why:** the first row of the state-derivation truth table in [01-architecture.md](01-architecture.md) is *"check ran but reached no verdict → `inconclusive`"*, and nothing in the schema carried that signal. The row was not computable. Its presence is now what makes a state `inconclusive`.

**Revert:** delete the field and the first row of the truth table. `inconclusive` then becomes unreachable, which is the state the contract was in before.

### 2. `telemetry.checks_run` on the ScanResult

**What:** a list of `{check_id, location, outcome}`, where outcome is `reported` / `clear` / `inconclusive` / `suppressed` / `error`.

**Why:** two things needed it. [10-measurement.md](10-measurement.md) defines `inconclusive_rate = inconclusive / (all checks that ran)` and that denominator existed nowhere. And design check 5 — *a check that ran is never silently omitted* — was unenforceable without a record of what ran. `core/models.py` now rejects a ScanResult whose check claims `reported` or `inconclusive` with no matching finding.

**A correction made during implementation:** the first version was a plain list of `check_id`s, and the validator demanded a finding or a suppression record for each. That wrongly rejected the ordinary case — a check that ran, found nothing wrong, and correctly said nothing. `clear` is the honest name for that outcome.

**Revert:** drop the field; `inconclusive_rate` becomes uncomputable and silent omission becomes undetectable.

### 3. `analysis` on `dns_answer` evidence

**What:** an optional object beside the raw DNS answer, holding our reading of it — a parse tree, a resolved SPF `include:` chain with its lookup count.

**Why:** [05-phase-1-first-tools.md](05-phase-1-first-tools.md) specifies exactly this as the Email scanner's evidence: *"the raw TXT record string, the parse tree, the resolved `include:` chain with its lookup count."* It is kept separate from the raw answer on purpose — the answer is the observation, the analysis is our interpretation, and a user checking our working needs to see which is which.

**Revert:** drop the field; evidence for SPF findings loses the working behind the conclusion.

### Also decided during implementation, and not in the documents

- **On a known-good corpus target, a `suspected` finding counts as a false positive.** [10-measurement.md](10-measurement.md) excludes `suspected` from precision, and separately says anything reported on a known-good target is a false positive by definition. Those two rules collide, and the collision was found by deliberately breaking the reference scanner: the injected false positive came back `suspected` and passed the gate. On an asset we know is correctly configured there is nothing to be uncertain about, so the hedge is a false positive wearing a hedge.
- **A corpus case may declare `expect_inconclusive`.** [10-measurement.md](10-measurement.md) measures the inconclusive rate *"where a definite answer is expected"*. A SERVFAIL fixture is not that. Such cases are excluded from the rate and asserted separately: the scanner must return `inconclusive`, and must not error.
- **A check whose subject does not exist is not recorded in `checks_run` at all.** `dmarc-pct-partial` on a domain with no DMARC record did not run. Recording it `clear` would claim we checked and found nothing wrong; recording it `inconclusive` would bury the one finding that matters under five restatements of it.

---

## v3.3 — live verification added to the Phase 1 definition of done (2026-08-25)

**What changed.** [05-phase-1-first-tools.md](05-phase-1-first-tools.md) gains a definition-of-done item: run the tool against real targets and hand-verify every finding. Recorded as [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done); the accuracy rules in [06-guidelines.md](06-guidelines.md) and the caveats in [10-measurement.md](10-measurement.md) were updated to match.

**Why.** Tools 1 and 2 both passed their gates at `precision 1.000` with six real defects still in them, every one found by a live run and none by the corpus. A corpus written by the scanner's author encodes the scanner's assumptions.

**Revert.** Remove the ADR, the DoD item and the two doc sections. Nothing depends on it structurally — the cost of reverting is that the next defects of that kind reach a user rather than the ledger.

---

## v3.4 — the calendar, and the foundation it needs (2026-08-25)

The client asked for differentiation that holds up in 2026 rather than 2022. Research surfaced three dated, checkable facts that were not true or not checkable when v3.1 was written: certificate lifetimes are collapsing on a published schedule (200 days from March 2026, 47 by 2029), roughly half of domains have no post-quantum protection against harvest-now-decrypt-later, and thousands of AI agent servers are exposed on the public internet.

**Strategy.** [ADR-020](02-decisions.md#adr-020--amends-adr-014-what-we-claim-now-that-the-ground-has-moved) amends ADR-014 with four claims — the deprecation clock, post-quantum exposure, certificate lifetime readiness, AI and agent exposure. **The three claims ADR-014 cut stay cut**; nothing in the research changes the judgement on attack paths or reachability.

**Contract.** [ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived) reopens the frozen Scanner Contract, deliberately and at two scanners rather than ten. Findings gain `materialises_at` (when a finding becomes true) and `derivation` (detected by observation, or derived by calculation, with confidence inherited from the premise). The five states and the truth table are untouched.

**Architecture.** [ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other) gives a run a shared asset graph so discovery can feed the tools that consume it, without scanners importing each other.

**Revert.** Drop the three ADRs, the four schema fields, and the graph from `ScanRun`. Existing findings default to `materialises_at: null` and `derivation: detected`, so nothing stored needs rewriting in either direction — which is the property that made doing this now cheap and doing it later expensive.
