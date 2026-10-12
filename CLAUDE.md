# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CURRENT STATE

This repo is being evolved to the v4 architecture.
Target: docs/18-v4-plan.md | Roadmap: docs/19-v4-roadmap.md | Migration: docs/20-migration-runbook.md
The tool-first strategy in docs/archive/ is SUPERSEDED. Do not follow it.

**MVP Alpha (decided 2026-10-12, [ADR-033](docs/02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred)).** The first release is one combined **Alpha**: customer scanning (**Light** for any domain; Light plus **passive Standard** for owners verified by DNS TXT, with the four testssl.sh checks held out until D56 is fixed), plus our internal server fleet assessed by a read-only **Linux agent** (PLANNED, not built). It adds **no new external scanners**: new value goes into the agent's modules. The flow engine is **minimal and deterministic**. Reports come in JSON, HTML and PDF, with an overall score and sub-scores, our branding, and AI summaries under a **mandatory fact-check test**. **Tool 4b is deferred past Alpha.** Scope: [docs/24](docs/24-alpha-scope.md). Report: [docs/25](docs/25-alpha-report-spec.md). **Working build plan: [docs/26](docs/26-alpha-build-sequence.md); tick its items as steps complete.**

**Where things stand (handoff, 2026-10-10).** Start with the ledger's handoff section, which lists every open item and its status: [docs/14-progress-ledger.md, "Handoff: open items"](docs/14-progress-ledger.md#2026-10-10--handoff-open-items-and-where-to-start). In short:
- **Shipped and merged through PR #41:** email v1.5.1, tls v1.4.0, domscout v1.3.2, web v1.0.5. Since PR #31: D28 and ADR-032 (`not_applicable`), D53, D52 and D54, each `core/` change after an independent review. Recent work: ADR-028 core redaction (D21), the read-only finding store, ADR-029 redaction receipts and `secret-exposed`, D48 (RFC 9525, no Common Name fallback), ADR-030 (UTS-46 hostnames, `idna` signed off), tls RFC citations with legacy-but-deployed exemptions, ADR-031 accepted (service hosts), and D31 (takeover fingerprints; BROKEN → UNDETERMINED).
- **Standing figure** (owned by [SPEC.md](SPEC.md)): 68 checks, 42 WORKING, 0 BROKEN, 26 UNDETERMINED. **38% have no evidence they work.**
- **Decided 2026-10-10:**
  - the IANA RDAP bootstrap licence is **signed off** (CC0 1.0; the caveat is in `tools/registry.yaml`);
  - D28's `.test` question is **approved**: special-use names get an explicit "expiry does not apply", never a silent pass, and expiry is proven with real recorded registry cases;
  - **company-domain canaries are skipped** for now.
- **Waiting on the operator:**
  - the value-add backlog's quick wins: they are not in the Alpha build plan (docs/26), so add any only on the operator's say-so.
- **Next:** **the Alpha build has started, following [docs/26](docs/26-alpha-build-sequence.md).** Step 0 (bring the decisions into the repo) is done. **Step 1, the contract extension, is done:** ADR-034, merged after an independent review. Next is **Step 1b, the D56 fix**: a safety-claim violation, because `testssl.sh --vulnerable` sends active probes ADR-023 says we never send. It goes in its own reviewed PR, ahead of the agent. After that comes the **agent ADR** (ADR-035, Step 2).
- **Ledgered, no action:** a WHOIS fallback for NIXI's TLDs (`.भारत` and `.இந்தியா` are not in the RDAP bootstrap).
- **Standing rules from the operator:**
  - Never push or merge without being told; merge with `--merge`.
  - Never rewrite history.
  - Keep the operator's company domains and the ERP host out of docs, evidence and PRs.
  - Real positives for secret checks come only from canaries, never from screening other people's domains.
  - An independent review before merging any change to `core/`.

## NON-NEGOTIABLE: extend, do not rebuild

These already exist in core/ and are validated. EXTEND them, never regenerate:
core/confidence.py, core/correlation.py, core/assetgraph.py, core/killswitch.py,
core/cost.py, core/evidence.py, core/store.py, core/state.py, core/replay.py,
core/measurement.py, core/registry.py, core/authz.py, core/ratelimit.py
The 4 files in contracts/ are the FROZEN contract — change only via a deliberate,
additive migration with an ADR, never ad hoc.
The 4 validated scanners (domscout, email, tls, web) must not be regenerated.
The only NEW top-level dirs in this migration are api/ and web/.
If a task seems to require rebuilding any of the above, STOP and ask me.

## Repository state

**Phase 0 is implemented; Tools 1 (Email), 2 (TLS), 3 (DomScout) and 4a (Website Scanner, Light) have shipped and pass their gates.** The Scanner Contract is frozen, `core/` services exist, the CLI runs, and the corpus harness gates on real numbers.

Scanners: `example` (reference), `email` (Tool 1, v1.5.2), `tls` (Tool 2, v1.4.1, cross-checked against testssl.sh, with a runtime testssl.sh wrap for legacy ciphers in Standard mode), `domscout` (Tool 3, Light, v1.3.3), `web` (Tool 4a, Light, passive only, v1.0.6). Check counts, gate numbers and status are owned by `SPEC.md` and `docs/21-scanner-catalogue.md`; do not restate them here.

Commands: `make install`, `make test`, `make lint`, `make typecheck`, `make licence-check`, `make corpus`, `make crosscheck`, `make targets-up`, and `scan run <tool> --target <t>`. Python 3.13.15, pinned in `.python-version`; dependencies via `uv`.

Read `docs/14-progress-ledger.md` for where things stand — including **standing observations**, which apply to every tool, not just the last one. To operate the CLI, read `docs/12-cli-runbook.md`. For the vulnerable test targets, `docs/13-test-targets.md` (`make targets-up`). To add a scanner, read `docs/how-to-add-a-scanner.md`.

## Documents

- `docs/18-v4-plan.md` — **current plan entry point** (v4). The v3.4 front door, `tools-and-features-list.md`, is archived in `docs/archive/`
- `SPEC.md` — **the canonical build specification: what each tool must do, current status, gates.** Authority for "what to build," replacing `docs/reference/product-spec.md` in that role.
- `docs/00-context.md` — product, strategy, standards
- `docs/01-architecture.md` — **the Scanner Contract, finding/evidence model, confidence engine**
- `docs/02-decisions.md` — ADRs 001–034
- `docs/03-roadmap.md` — phases 0, **0b (foundation for the calendar)**, 1–7 with accuracy gates
- `docs/04-phase-0-foundations.md`, `docs/05-phase-1-first-tools.md` — task-level plans
- `docs/06-guidelines.md` — rules for all code
- `docs/07-open-questions.md` — what is undecided
- `docs/15-iot-scanner.md` — **the IoT & Device Security Scanner**: a distinct tool, its checks, and the safety rules that are stop-the-line
- `docs/14-progress-ledger.md` — **what has been built, what broke, what is owed**; append after each phase or tool
- `docs/13-test-targets.md` — the vulnerable corpus targets, how to run them, and what we deliberately do not scan
- `docs/12-cli-runbook.md` — **operator guide for the `scan` CLI**: every command, real output, exit codes, troubleshooting
- `docs/17-testing-runbook.md` — **how to prove the scanners are correct**: the test layers, the corpus, the labs, live verification, CI. Copy-pasteable
- `docs/16-learning-map.md` — **what the developer needs to learn**, dev and security, tiered by when it is needed
- `docs/how-to-add-a-scanner.md` — the practical guide, written by building the reference scanner
- `docs/21-scanner-catalogue.md` — **every shipped check**: what it finds, mode, highest state and its evidence, working/broken. Derived from code; regenerate it, don't hand-edit. Status defers to `SPEC.md` and the ledger
- `docs/22-differentiators.md` — **what we can claim that most scanners can't**, each line TRUE / PARTIAL / PENDING with a link to its evidence (a test, a ledger row or a verification archive). A claim with no evidence link stays out. Numbers live in SPEC.md and the ledger; this file links to them
- `docs/24-alpha-scope.md`, `docs/25-alpha-report-spec.md`, `docs/26-alpha-build-sequence.md` — **the MVP Alpha** (ADR-033): its scope, its report, and **the working build plan** (tick items as steps complete)
- `docs/23-value-add-backlog.md` — **a plan only**: candidate features from the live runs, each with its source, customer value, guardrail, effort and status (PROPOSED). Nothing in it is built or scheduled
- `docs/08-changelog.md` — v2→v3, v3→v3.1, and the v3.2 additive contract changes made during Phase 0, with revert notes
- `docs/09-ownership-verification.md` — the legal gate on active scans; methods per target type, audit record, interim allowlist schema
- `docs/10-measurement.md` — **how precision/recall/inconclusive-rate are computed**; read before touching the corpus harness
- `docs/11-operations.md` — incident response, observability, secrets, data retention
- `docs/reference/product-spec.md` — full 18-tool / 12-feature catalogue (v2 Parts A+B, verbatim; its "Phase:" labels are superseded by `03-roadmap.md`)
- `docs/archive/tools-and-features-list-v2.md` — original, unchanged

## Which document is authoritative — read this before editing any of them

This set has drifted before, in both directions: a document restating another's facts and then falling behind it, and a second document appearing to cover ground the first already owned. **Each fact has exactly one home. Everywhere else links to it.**

| Question | The one authority |
|---|---|
| What are we building, what must each tool do, what is its status? | **`SPEC.md`** |
| Why was it decided that way? | `docs/02-decisions.md` (the ADRs) |
| When, in what order, against what gate? | `docs/03-roadmap.md` |
| What actually happened, what broke, what is owed? | `docs/14-progress-ledger.md` |
| How do I run it? | `docs/12-cli-runbook.md` |
| How do I test it, and run the labs? | `docs/17-testing-runbook.md` |
| How is accuracy computed? | `docs/10-measurement.md` |

**Historical, and deliberately not maintained** — do not "fix" these to match today:

- `docs/archive/` — the original v2 proposal, byte-for-byte. **Never edit it.** `docs/08-changelog.md`'s revert instructions copy from it verbatim, and it is the only record of what was originally asked for.
- `docs/reference/product-spec.md` — the v2 catalogue, preserved. Superseded by `SPEC.md` for anything you intend to build.

**Rules that keep it from drifting again:**

1. **Do not restate a fact that another document owns — link to it.** A number copied into a second place is a number that will be wrong in one of them.
2. **A change that alters a decision updates the ADR**, not only the place it surfaces, and is recorded in `docs/08-changelog.md`.
3. **Do not add a new status or summary document.** `SPEC.md` holds current state; the ledger holds history. A third view of the same thing is how this happened before.
4. **When two documents disagree, fix the wrong one and say so** — do not add a third document explaining the difference.

## The product

A security scanning SaaS. Users scan assets they own; findings come with **evidence and calibrated confidence**. Every scanner exposes three modes: **Light** (passive, no auth needed, free), **Standard** (active, requires verified ownership), **Deep/Validated** (Standard + proof, Business tier).

## Build strategy — API-first (ADR-026, supersedes ADR-001 and ADR-012)

The v4 plan (`docs/18-v4-plan.md`) replaces tool-first. `api/` and `web/` are in scope from Phase 1 of the v4 migration: every capability goes through `api/` first, and `web/` is a thin client of it with no logic of its own. Accounts, ownership verification, billing and Free/Pro tiers are part of the v4 Phase 1 MVP and are no longer deferred to Phase 6. For order and steps, see `docs/19-v4-roadmap.md` and `docs/20-migration-runbook.md`.

Each scanner is still gated on accuracy against a ground-truth corpus before it ships. The **Scanner Contract** (Phase 0) is still the foundation: a frozen finding/evidence schema and `BaseScanner` interface that `api/` wraps rather than replaces. Changing it is a migration, not an edit.

The contract was audited in v3.1 before freezing and gained: a `ScanRun` entity, `status`/`status_history`, `instance_key` + reserved `location: "$"` + `renamed_from` in the ID scheme, `detection_methods[]` with independence classes, kind-specific evidence shapes, and `related_assets[]`. Do not reintroduce the simpler versions.

## Hard constraints (see `docs/06-guidelines.md`)

1. **No exploitation.** No shells, no state changes, no data extraction, no brute-force, no load testing. Blind bugs are proven via out-of-band callbacks and canary tokens. This is absolute in Light and Standard and for the IoT scanner. **ADR-025** carves one future exception — controlled exploitation in Deep mode, under a signed authorization agreement, opt-in per scanner, never for state changes / data extraction / IoT — but it is gated behind Deep mode, the OOB server and the Q5 legal artifact, none of which exist, so **today the rule is still absolute everywhere.**
2. **No active scan without verified ownership**, enforced deny-by-default in `core/authz.py` — from the first Standard-mode check, not from Phase 6. See `docs/09-ownership-verification.md`.
3. **Licence rule (ADR-003):** permissive OSS may be embedded; commercial/restrictive/unclear may not. Forbidden: **Nmap** (use naabu — its licence bars inclusion *even inside a container*), Nessus, Burp, Acunetix/Invicti, **Semgrep's rules** (use Opengrep + own rules), **TruffleHog** (AGPL — use Gitleaks + own validator), OpenVAS. We import their output instead.
4. **GPL tools run as separate processes only** — testssl.sh, ScoutSuite, and **MobSF (GPLv3, a Django app: run as its own service, never import it)**. Never linked, never copied. This applies to data too: **Wappalyzer's fingerprint database and its forks are GPL-3.0** and must not seed our fingerprint DB.
5. **Never store customer secrets** — redact at capture time, not at display time.
6. **Never say "compliant"** — only "compliance readiness" (ADR-011).

## Accuracy rules — these are the product

- **Severity, confidence and state are three separate axes.** Triage sorts by `severity_weight × confidence`.
- States: `confirmed` / `highly_likely` / `suspected` / `informational` / **`inconclusive`**. Returning `inconclusive` is correct and expected — never guess, never silently drop.
- **Every finding needs a control-vs-test evidence pair.** "The server errored" is not evidence.
- **Version strings lie** (distros backport patches). Version-only findings cap at `suspected`, confidence ≤ 0.6.
- **Precision over recall.** A new detection requires both a positive and a negative corpus case, an `independence_class`, and a justified prior.
- **The corpus proves regression, not correctness.** A corpus written by the scanner's author encodes the scanner's assumptions. Run each tool against real targets and hand-verify before calling it done (ADR-017). Six real defects survived corpora at precision 1.000.
- **A gate number is read with its claim count.** Precision counts only `confirmed`/`highly_likely`, so 1.000 over 5 claims and over 500 are the same number and not the same evidence.
- **`state` is computed by `core/state.py`, never hand-set** by a scanner. `confirmed` requires validation to have run and passed.
- **Gates are three numbers:** precision, recall, and inconclusive rate (≤15%) — see `docs/10-measurement.md`. Recall is corpus-relative for DNS enum and Web Light; never publish it as absolute.
- Confidence is **provisional** until calibration in Phase 4, and calibrates per (scanner × detection_method), never per `check_id`.

## Architectural invariants

- Scanners **never** construct their own HTTP/DNS clients — everything ambient comes from `ScanContext`, which is how rate limiting, scope enforcement and the kill switch stay guaranteed.
- Scanners **never** import from each other; shared logic moves to `core/`.
- Deterministic finding IDs: `sha256(scanner + check_id + target + normalise(location) + instance_key)`, so re-scans preserve history. `location: "$"` means target-level; `renamed_from[]` preserves history across `check_id` renames.
- Bump `scanner_version` whenever results change.
- Every row carries `org_id` from the first migration, even pre-multi-tenancy.
- Count per-scan cost (requests, wall time, AI tokens) from the very first scan.

## What we claim (ADR-020, amends ADR-014)

Four claims added in v3.4, all *observation plus rule* rather than new research capability:
**the deprecation clock** (what breaks on a date, not just what is broken), **post-quantum exposure**, **certificate lifetime readiness**, **AI and agent exposure** (MCP servers, agent panels, model endpoints — passive detection only), and **the IoT & Device Security Scanner** (ADR-021) — a distinct tool whose claim is that it is *safe* to point at fragile devices.

They are worth little without the proof layer: evidence, `inconclusive`, calibrated confidence. A date nobody believes is just another alert.

**Prove, connect, close (ADR-022)** is the aggressive-but-safe mitigation loop, entirely within ADR-004: make the target *prove* the bug via out-of-band callback (never exploit it), *connect* findings that compose into one attack story, *close* a finding by re-running the exact test that proved it. Aggressive proof, never intervention — do not let 'offensive' drift into touching a target.

## Descoped — do not reintroduce (ADR-014)

Three claims were cut after validation because a two-person team cannot own them against funded incumbents. If asked to build them, flag the ADR first:

- **Chokepoint / attack-path analysis** — Wiz and XM Cyber's core product; also depended on Phase 5 data from Phase 4. Phase 4 ships basic same-asset correlation only.
- **Reachability analysis** — Endor Labs' entire product. Supply-chain scanning does direct-dependency matching and says plainly that we do not do reachability.
- **"Almost nobody does BOLA testing"** — false since Dec 2025. Build the feature; never make the novelty claim.

Also: **naabu is port discovery only.** Our service fingerprinting is scoped to ~50 services, with no claim of Nmap parity.

## Working on these docs

The document set is cross-linked; when changing a decision, update `docs/02-decisions.md` (the ADR) rather than only the place it surfaces, and record the change in `docs/08-changelog.md`. Never edit `docs/archive/`.
