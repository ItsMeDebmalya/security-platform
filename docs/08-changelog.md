# 08 — Changelog and Revert Notes

*What changed from v2 to v3, why, what was deferred, and exactly how to go back if any of it turns out to be wrong.*

---

## The original is preserved

**[archive/tools-and-features-list-v2.md](archive/tools-and-features-list-v2.md)** — the v2 document, byte-for-byte unchanged apart from the two-line ARCHIVED banner added at the top in v4.0-pre (see below).

Nothing was deleted. Every tool description, feature list, differentiator and decision from v2 survives, either in the working documents or in [reference/product-spec.md](reference/product-spec.md).

**To revert entirely:**
```bash
tail -n +3 docs/archive/tools-and-features-list-v2.md > tools-and-features-list.md  # skip the 2-line ARCHIVED banner
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

---

## v3.4a — the IoT & Device Security Scanner (2026-08-25)

**What changed.** IoT becomes a distinct tool with its own gate, corpus and plan ([15-iot-scanner.md](15-iot-scanner.md)), in a new Phase 3a, rather than checks bolted onto the Network Scanner. [ADR-021](02-decisions.md#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family).

**Why a tool and not a check family.** It takes a *network* rather than a domain, its primary output is an asset inventory, it is the only tool that runs inside the perimeter, and its accuracy problem is inference rather than observation. Also: a differentiator has to be nameable, and "our network scanner also does some IoT checks" is not a pitch.

**The compliance angle was researched and dropped.** India — the first market — has no mandatory IoT security regime: MTCTE is pre-market certification of manufacturers, and DoT's consumer-IoT guidance is advisory. There is no dated cliff to sell against, so the tool is positioned on capability rather than a calendar.

**A hard safety rule was added** to [06-guidelines.md](06-guidelines.md): device-class rate ceilings are floors rather than defaults, one connection per device, never repeat an unanswered probe, read-only verbs only. Scanning a device network is the most dangerous thing this product does.

**Revert.** Drop ADR-021, `15-iot-scanner.md` and Phase 3a. The safety rules should stay regardless — they apply to anything that talks to constrained hardware.

---

## v3.4b — prove, connect, close (2026-08-25)

**What changed.** The mitigation side of the product — long a set of slogans — gets a real design in [ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target): the validation engine promoted to flagship (prove), a same-run correlation pass over the asset graph (connect), and a finding store plus `scan verify` (close). Prioritisation falls out of correlation. Two Phase 0b tasks added: 0b.8 finding store, 0b.9 correlation pass.

**Why.** The client asked for aggressive, mitigation-focused capability. "Offensive" read literally would break [ADR-004](02-decisions.md#adr-004--no-exploitation-ever), which is not reversible. The ownable version is aggressive *proof* — making the target demonstrate the bug — not intervention. Confirmed with the client that this was the intent.

**The gap this closes honestly.** "We verify your fix" has been a differentiator since v2 with no design behind it. It is now specified, and its dependency (findings that persist between scans) is named as foundation work rather than assumed.

**Revert.** Drop ADR-022, tasks 0b.8/0b.9, and the two architecture sections. The finding store is the only real infrastructure; correlation and prioritise are framing over data already produced.

---

## v3.4c — 0b.1 implemented: dated and derived findings land in the contract (2026-08-28)

*Recorded here for the same reason as v3.2 — [ADR-002](02-decisions.md#adr-002--freeze-the-scanner-contract-before-writing-tool-1) makes a contract change a migration rather than an edit, even an additive one, and even one the ADR already approved.*

**What changed.** [ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived) is implemented. Four fields on `Finding`, all additive and all optional:

- `materialises_at` — a date or null. Null means true now, which is every finding before this and almost every finding after it.
- `materialises_reason` — required exactly when `materialises_at` is set, forbidden otherwise.
- `derivation` — `"detected"` (default) or `"derived"`.
- `derived_from` — the premise finding's `id`, required exactly when `derivation` is `"derived"`, forbidden otherwise.

`contracts/finding.schema.json` and `core/models.py` both gained the fields, with `Finding` rejecting either co-dependency violation at construction — loud, not silent, matching every other validator in that file. `core/state.py` was **not touched**, per the ADR: the truth table does not move for a dated finding.

`core/confidence.py` gained `ConfidenceEngine.inherit(premise_confidences)`, a second and deliberately separate path from `combine()`. It returns the minimum of the given premise confidences — never more confident than the weakest premise, per ADR-018, and per ADR-022 when a derivation chains from several premises. It does not touch `combine()`'s log-odds machinery at all: pushing a calendar date through a likelihood ratio would mean inventing one, which is exactly what the ADR forbids.

`core/measurement.py`'s `Observation` gained a `derivation` field (default `"detected"`), and `CaseScore`/`TierSummary` now carry `tp_detected` / `fp_detected` / `tp_derived` / `fp_derived` alongside the combined `tp`/`fp`, with `precision_detected` and `precision_derived` properties and a `claims: {detected, derived}` block in `to_dict()`. **The gate itself reads only the combined numbers, unchanged** — this adds a breakdown, it does not change what passes or fails.

**Corpus impact: none.** No scanner emits a dated or derived finding yet (that is Tool 2 v1.1, a later task) — this task only makes it possible. `make corpus` shows email and tls unchanged at `1.000/1.000`.

**Judgement calls made, not fully specified by the ADR:**
- `materialises_at` is typed as an ISO date (`format: "date"`), not a datetime, since a certificate-lifetime rule or a deprecation deadline is stated in days, not seconds — matching `docs/15-iot-scanner.md`'s and the roadmap's framing of "the calendar" as dates.
- `inherit()` takes a plain list of floats rather than a list of `Finding`s or ids, mirroring `combine()`'s `Signal`-list shape at the *value* level; the caller (a future scanner or the correlation pass, 0b.9) is responsible for resolving `derived_from` to a confidence before calling it.
- The measurement split counts `tp`/`fp` by derivation only, not `fn`. `Expected` corpus fixtures have no derivation of their own — a false negative is a thing the scanner failed to claim, and until a corpus actually contains derived expectations (no scanner emits them yet) there is nothing to split there. Revisit when Tool 2 v1.1 lands derived findings in a corpus.

**Revert.** Drop the four fields from the schema and model, the two new validators, `ConfidenceEngine.inherit`, and the four new `CaseScore`/`TierSummary` fields plus the `claims` block in `to_dict()`. Every finding stored today already has `derivation: "detected"` and `materialises_at: null` in effect (the fields did not exist), so nothing needs rewriting either direction.

---

## v4.0-pre — v4 migration housekeeping (2026-10-02)

**What changed.**
- `tools-and-features-list.md` (the v3.4 front door) moved to [archive/tools-and-features-list.md](archive/tools-and-features-list.md). Its internal relative links were left as they were and no longer resolve from `docs/archive/`. That is accepted for an archived file.
- Both archive files, `archive/tools-and-features-list.md` and `archive/tools-and-features-list-v2.md`, gained a two-line banner at the top: `> ARCHIVED — superseded by docs/18-v4-plan.md. Do not use for current direction.` followed by a blank line. This is the only edit ever made to the v2 file. The revert step under "The original is preserved" now skips those two lines.
- v4 plan documents added (docs/18 ~526 lines, docs/19 ~453 lines, docs/20 ~297 lines): [18-v4-plan.md](18-v4-plan.md), [19-v4-roadmap.md](19-v4-roadmap.md), [20-migration-runbook.md](20-migration-runbook.md).
- `CLAUDE.md` and `SPEC.md` now point to `docs/18-v4-plan.md` as the plan entry point instead of `tools-and-features-list.md`.
- [ADR-026](02-decisions.md#adr-026--adopt-api-first-architecture-supersedes-adr-001-tool-first-and-adr-012-platform-deferral) adopts API-first and supersedes both [ADR-001](02-decisions.md#adr-001--build-tools-first-platform-second) (tool-first) and [ADR-012](02-decisions.md#adr-012--defer-all-platform-billing-and-account-work-to-phase-6) (defer platform, billing and account work to Phase 6), because the v4 Phase 1 MVP includes accounts, ownership verification, billing and Free/Pro tiers. Both ADRs are marked superseded, and their text is kept. In `CLAUDE.md`, the build-strategy section now points to ADR-026 and the v4 plan, the "no UI/accounts/billing before Phase 6" rule is removed, and the section says that work is in v4 Phase 1. `CLAUDE.md`'s "Repository state" section now includes DomScout (Tool 3) as shipped. Revert: remove ADR-026 and the superseded markers on ADR-001 and ADR-012, then restore those `CLAUDE.md` sections from git.

**Revert.**
```bash
tail -n +3 docs/archive/tools-and-features-list.md > tools-and-features-list.md && git rm -q docs/archive/tools-and-features-list.md
tail -n +3 docs/archive/tools-and-features-list-v2.md > /tmp/v2 && mv /tmp/v2 docs/archive/tools-and-features-list-v2.md
```
Then restore the entry-point lines in `CLAUDE.md` and `SPEC.md`, and the revert step above, to point at `tools-and-features-list.md` again.

---

## v4.0-pre.1 — ADR-027, fixtures stand in for real services only on recorded evidence (2026-10-08)

**What changed.**
- [ADR-027](02-decisions.md#adr-027--a-fixture-may-stand-in-for-a-real-service-only-on-recorded-evidence) was added. A corpus generator may hand-write a third party's response only if a cited recording of the real service backs it. Generated HTTP responses carry realistic header sets, and a contract test is to reject any HTTP fixture with no headers.
- It was prompted by the corpus-fidelity audit (ledger, 2026-10-08). Two `domscout` checks pass their gate and are broken in production (D28, D31).
- `CLAUDE.md` now lists ADRs 001–027.
- `SPEC.md` marks `email` "corpus-validated, live-unverified" (D35) and records the two broken `domscout` checks.
- No code, fixture or contract changed.

**Revert.** Delete the ADR-027 section from `docs/02-decisions.md`, restore "001–026" in `CLAUDE.md`, and remove the two `SPEC.md` notes. The contract test it calls for does not exist yet, so there is nothing to remove from code.

## v4.0-pre.2 — ADR-017 amended: a check must fire against a real positive before it ships (2026-10-08)

**What changed.**
- [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done) gained a clause: every new check must be shown to fire against a real positive (live, hand-verified, cited) before it ships. A corpus positive does not count. It was prompted by the fourth advertised check found that cannot fire in production (ledger D37, after D28 and D31).
- `docs/how-to-add-a-scanner.md` §7 has the matching checklist item.
- `SPEC.md` now states the catalogue's standing figure (63 checks: 23 WORKING, 3 BROKEN, 37 UNDETERMINED) and declares that no `tls` check can reach `confirmed`.
- No code, fixture or contract changed.

**Revert.** Delete the "Amended 2026-10-08" paragraph from ADR-017, the §7 checklist item, and the two `SPEC.md` additions.

## v4.0-pre.3 — D39: DNS queries go to the resolver they name (2026-10-08)

**What changed.**
- `core/dns.py` `SystemResolver` routes each query to the named resolver, with one dnspython `Resolver` per upstream. It labels each answer with the server that answered. A failing named resolver is no longer replaced silently by another.
- `FakeResolver` honours the `resolver` argument (`by_resolver`) and labels its answers, so the corpus can express disagreement.
- `cli/corpus.py`: a case may set `resolvers:` (its primary first).
- Two recorded corpus cases (`disagree-stale-spf`, `disagree-stale-dkim`) come from `corpus/generators/email_recorded.py`.
- `email` `spoofing-possible` validation re-reads SPF as well as DMARC.
- Ruff excludes `corpus/crosscheck/email-live/`, which is checksummed evidence.
- The email corpus fixtures were re-recorded. About 386 change their `resolver` field from `null` to the resolver asked, and the wildcard probe labels are new. No outcome changes.
- `spoofing-possible` validation shows the SPF record it re-read in its evidence. A validation predicate may now return `None`, meaning "could not validate" (`unavailable`).
- Runbook §10: a resolver reachability check before live runs.

**Revert.** Restore the previous `SystemResolver` and `FakeResolver` from git, and drop the two cases and their fixtures. Not advised: it restores evidence that names a resolver which never answered.

## v4.0-pre.4 — ADR-017 amended: cited RFCs must be current (2026-10-08)

**What changed.**
- ADR-017 gained a clause: every RFC a check cites is confirmed current against the RFC Editor's "Obsoleted by" field, with the same weight as the must-fire rule. how-to-add-a-scanner §7 has the matching checklist item.
- `cli/rfcs.py` and `make rfc-check` check every `rfc-editor.org` citation in `scanners/` against the RFC Editor's metadata. The check needs the network and is not in `make test`.
- The ledger records the primary-source confirmation of RFC 9989 (D44), and D48 (four obsoleted RFCs in `tls`).

**Revert.** Delete the clause, the checklist item, `cli/rfcs.py` and the Makefile target.

## v4.0-pre.5 — ADR-017 amended: dual reading and worst-case severity; email reads DMARC under RFC 9989 (2026-10-09)

**What changed.**
- ADR-017 gained two rules. Read both standards where they disagree, capping at `suspected`. Give a receiver-dependent finding the severity of its worst case, with the state carrying the doubt.
- `email` v1.3.0 finds the applicable DMARC record by RFC 9989's DNS tree walk. v1.4.0 reads DMARC records under RFC 9989 first:
  - `pct` is dual-read;
  - an absent `p` means `p=none`;
  - tag order is free (an RFC 7489-only issue);
  - `t` and `np` are read.
- Three new checks: `dmarc-obsolete-tags`, `dmarc-test-mode`, `dmarc-np-weaker`. `dmarc-*` and `spoofing-possible` references now cite RFC 9989.
- Corpus changes: a real recorded case (`real-obsolete-pct`, cloudinary.com) and two synthetic ones (`dmarc-test-mode`, `dmarc-np-weaker`). `dmarc-partial-rollout`'s expectation gains `dmarc-obsolete-tags`.

**Revert.** Delete the ADR-017 paragraph. Reverting the scanner reintroduces the false claims of ledger D44.

## v4.0-pre.6 — ADR-028: core redacts secrets at every storage point (D21) (2026-10-09)

**What changed.**
- New `core/redaction.py`, the only redactor. It covers token patterns and whole PEM private-key blocks, including the truncation-gap cases from Tool 4a. Public key material is never redacted: certificates, public keys, DNS records and DKIM `p=` values.
- Redaction is applied at every storage point:
  - HTTP captures: URL, header names and values, bodies;
  - recorded and replayed fixtures, with legacy fixtures cut on replay;
  - evidence however it is built;
  - `Finding` text: the only way in, so create, construction, deserialisation and store load all redact; `model_construct` is blocked and `model_copy` re-validates;
  - `ScanError`, CLI output, progress, and uncaught exceptions.
  - the store at rest: loading rewrites a pre-ADR-028 row that held a secret, with `secure_delete` on. When the rewritten id already belongs to a newer row, that row keeps its status and history and the legacy row is only deleted. A store is swept this way once, when it is first opened (`PRAGMA user_version = 1`).
- Truncation redacts first: `cap_text` and `cap_prefix` are the only cuts.
- **`web`'s scanner-side workaround is removed:** `_strip_private_keys` and its PEM machinery, and the `pre_redacted` path. Its unit tests moved to `tests/core/test_redaction_ported.py`. The web tests that depended on old core's fixtures now build legacy fixtures explicitly.
- `CLAUDE.md` lists ADRs 001–028. `how-to-add-a-scanner` §7 says: never write your own redactor, never slice raw text.

**Revert.** Not advised: it re-opens hard constraint 5. If needed, revert the merge commit. That restores web's workaround with it.

## v4.0-pre.7 — a read-only finding store opens (2026-10-09)

**What changed.**
- A finding store that cannot be written opens read-only: copied into memory, its pre-ADR-028 rows are redacted there, and the file is never written. Writes raise `ReadOnlyStoreError`.
- `scan run --store` and `scan verify` refuse a read-only store before scanning, exit 1.
- ADR-028 clause 6 says so.

**Revert.** Revert the merge commit. A read-only store then fails to open again.

## v4.0-pre.8 — ADR-029: redaction receipts, and a receipt on public content is a finding (2026-10-09)

**What changed.** This is an additive contract migration.
- **`contracts/evidence.schema.json`** gains an optional `redaction_receipts: [{kind, count, where}]` (`$defs/redaction_receipt`, with `additionalProperties: false`). The existing `redactions` list is unchanged.
- **`contracts/finding.schema.json`** gains an optional `redaction_receipts`, the evidence's receipts rolled up. The model computes it and never takes it from input.
- **Core:**
  - `core/http.py` records receipts at capture, writes them to fixtures and replays them.
  - `core/evidence.py` keeps a capture's receipts and counts what it redacts itself.
  - `core/redaction.py` records receipts by field path.
  - New `core/exposure.py`: `secret_exposure_findings`, `check_runs` and the contract check, `unreported_exposures`.
- **Scanners:**
  - `email` v1.5.0 and `domscout` v1.1.0 call the helper. Each gains `secret-exposed`, UNDETERMINED with no real positive yet.
  - `web` v1.0.5 passes the capture's receipts into its evidence. It does not call the helper, because `web-secret-in-response` reports the same thing.
- **Corpus:** three new cases, `email/secret-in-txt`, `email/secret-in-txt-clean` and `domscout/takeover-secret`, each holding AWS's documented example key. The gates still pass: email has 442 checks and 30 claims, domscout 58 checks and 1 claim.
- **Review fixes:** side-dict keys are redacted again, and a scan's `ExposureLog` (`ScanContext.exposures`) sees every public capture, not only cited evidence.
- **Tests:** `tests/core/test_redaction_receipts.py` and `tests/contract/test_secret_exposure_contract.py`.

**Revert.** Revert the merge commit. Evidence stored with receipts stays valid against the old schema only if the field is dropped, so a revert also needs a migration that strips `redaction_receipts`.

## v4.0-pre.9 — D48: hostname matching follows RFC 9525, with no Common Name fallback (2026-10-09)

**What changed.**
- `core/tls.py`: `covers_hostname` matches subjectAltName DNS names only, and OpenSSL's hostname reading is asked with `hostname_checks_common_name = False`. RFC 9525 §2 says "The Common Name RDN MUST NOT be used to identify a service". RFC 6125, which allowed the fallback, is obsoleted by RFC 9525.
- `tls` v1.3.0: cites RFC 9525. A CN-only certificate's mismatch says why, and no longer calls the certificate "valid for" its CN.
- Corpus: a new case, `cn-only`. tls now has 228 checks and 6 claims, PASS. The lab minter gains `omit_san`.
- **Review fix:** `iPAddress` SANs are parsed, and an IP target is matched by address (RFC 9525 §6.4), never against a DNS name or the CN. Without it, dropping the fallback gave a false mismatch on a valid IP certificate. U-label servernames are compared as A-labels. A name containing ß, ς, ZWNJ or ZWJ, which IDNA 2003 and UTS-46 encode differently, is `inconclusive` rather than judged by either reading. An IPv6 zone id no longer stops an address match.
- The ledger records under D38 whether the two hostname readings are now independent.

**Revert.** Revert the merge commit. RFC 6125's Common Name fallback then returns in both readings, and IP SANs are no longer read.

## v4.0-pre.10 — ADR-017 amended: legacy-but-deployed RFC citations; tls v1.3.1 (2026-10-09)

**What changed.**
- `make rfc-check` reports an obsoleted RFC listed in `tools/rfc-exemptions.yaml` as exempt. Each exemption needs a reason, the successor that was read, and evidence; `tests/cli/test_rfcs.py` enforces this offline in CI.
- `tls` v1.3.1:
  - `tls-weak-cipher` and `tls-no-forward-secrecy` cite RFC 9325 (§4, §7.3), which obsoletes RFC 7525.
  - `tls-chain-incomplete` cites RFC 9846 §4.5.1 and keeps RFC 5246 §7.4.2.
  - `tls-no-certificate-transparency` keeps RFC 6962. Both kept RFCs are exempt.
- Ledger: canaries are the approved way to get real positives for secret checks.

**Revert.** Revert the merge commit. `make rfc-check` then fails on RFC 5246, 6962 and 7525 again.

## v4.0-pre.11 — ADR-030: hostnames encoded as browsers encode them; tls v1.4.0 (2026-10-09)

**What changed.**
- `core.tls.a_label` encodes a non-ASCII hostname with UTS-46 non-transitional processing, using `idna`, now a direct dependency. That is the WHATWG URL Standard's choice.
- Our matcher, the SNI and OpenSSL's hostname check all use the encoder's output. Python's IDNA 2003 codec no longer runs.
- A name that does not encode is `inconclusive`. This replaces the D48 stopgap, which made every name with ß, ς, ZWNJ or ZWJ `inconclusive`.
- `tools/registry.yaml` gains `idna`, signed off by Debmalya Dey on 2026-10-10.

**Revert.** Revert the merge commit. The stopgap returns, and `idna` is transitive again.

## v4.0-pre.12 — ADR-031: service hosts (2026-10-10)

**What changed.** A decision only; there is no code yet.
- Service hosts are read-only public endpoints, computed per target.
- The RDAP bootstrap (RFC 9224) is vendored, with a 90-day freshness limit, and rdap.org is dropped.
- An unfollowed redirect is reported as what happened.
- The confidentiality of target names sent to service hosts is stated, and ledgered as D51.
- The canary policy for secret checks is in the ledger.

**Revert.** Delete ADR-031. Nothing implements it yet.

## v4.0-pre.13 — D31: takeover fingerprints judge recorded provider responses; domscout v1.2.0 (2026-10-10)

**What changed.**
- The S3, Heroku and GitHub Pages fingerprints judge the provider's `404` unclaimed-name body, fetched over plain `http://`.
- S3 recognises regional and website endpoints.
- The evidence is in `corpus/crosscheck/d31-provider-responses/`.
- `takeover-positive` is rebuilt from the recording, and the GitHub cases fetch over http.

**Revert.** Revert the merge commit. S3 and Heroku then go back to NXDOMAIN-only, which never fires live, and GitHub Pages back to https, which never fires live.

