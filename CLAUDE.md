# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

**Phase 0 is implemented; Tools 1 (Email) and 2 (TLS) pass their gates.** The Scanner Contract is frozen, `core/` services exist, the CLI runs, and the corpus harness gates on real numbers.

Scanners: `example` (reference), `email` (Tool 1 — 17 checks, 1.000/1.000, 16-case corpus), `tls` (Tool 2 — 13 checks, 1.000/1.000, 14-case corpus, cross-checked against testssl.sh).

Commands: `make install`, `make test`, `make lint`, `make typecheck`, `make licence-check`, `make corpus`, `make crosscheck`, `make targets-up`, and `scan run <tool> --target <t>`. Python 3.12+, dependencies via `uv`.

Read `docs/14-progress-ledger.md` for where things stand — including **standing observations**, which apply to every tool, not just the last one. To operate the CLI, read `docs/12-cli-runbook.md`. For the vulnerable test targets, `docs/13-test-targets.md` (`make targets-up`). To add a scanner, read `docs/how-to-add-a-scanner.md`.

## Documents

- `tools-and-features-list.md` — entry point and index
- `docs/00-context.md` — product, strategy, standards
- `docs/01-architecture.md` — **the Scanner Contract, finding/evidence model, confidence engine**
- `docs/02-decisions.md` — ADRs 001–022
- `docs/03-roadmap.md` — phases 0, **0b (foundation for the calendar)**, 1–7 with accuracy gates
- `docs/04-phase-0-foundations.md`, `docs/05-phase-1-first-tools.md` — task-level plans
- `docs/06-guidelines.md` — rules for all code
- `docs/07-open-questions.md` — what is undecided
- `docs/15-iot-scanner.md` — **the IoT & Device Security Scanner**: a distinct tool, its checks, and the safety rules that are stop-the-line
- `docs/14-progress-ledger.md` — **what has been built, what broke, what is owed**; append after each phase or tool
- `docs/13-test-targets.md` — the vulnerable corpus targets, how to run them, and what we deliberately do not scan
- `docs/12-cli-runbook.md` — **operator guide for the `scan` CLI**: every command, real output, exit codes, troubleshooting
- `docs/how-to-add-a-scanner.md` — the practical guide, written by building the reference scanner
- `docs/08-changelog.md` — v2→v3, v3→v3.1, and the v3.2 additive contract changes made during Phase 0, with revert notes
- `docs/09-ownership-verification.md` — the legal gate on active scans; methods per target type, audit record, interim allowlist schema
- `docs/10-measurement.md` — **how precision/recall/inconclusive-rate are computed**; read before touching the corpus harness
- `docs/11-operations.md` — incident response, observability, secrets, data retention
- `docs/reference/product-spec.md` — full 18-tool / 12-feature catalogue (v2 Parts A+B, verbatim; its "Phase:" labels are superseded by `03-roadmap.md`)
- `docs/archive/tools-and-features-list-v2.md` — original, unchanged

## The product

A security scanning SaaS. Users scan assets they own; findings come with **evidence and calibrated confidence**. Every scanner exposes three modes: **Light** (passive, no auth needed, free), **Standard** (active, requires verified ownership), **Deep/Validated** (Standard + proof, Business tier).

## Build strategy — tool-first (ADR-001)

Scanners are built **one at a time as standalone CLI tools**, each gated on accuracy against a ground-truth corpus, before the website exists. The site is Phase 6. Do not propose building UI, accounts, or billing before then.

The mitigation for tool-first's failure mode is the **Scanner Contract** (Phase 0): a frozen finding/evidence schema and `BaseScanner` interface. Everything depends on it. Changing it after Phase 1 is a migration, not an edit.

The contract was audited in v3.1 before freezing and gained: a `ScanRun` entity, `status`/`status_history`, `instance_key` + reserved `location: "$"` + `renamed_from` in the ID scheme, `detection_methods[]` with independence classes, kind-specific evidence shapes, and `related_assets[]`. Do not reintroduce the simpler versions.

## Hard constraints (see `docs/06-guidelines.md`)

1. **No exploitation.** No shells, no state changes, no data extraction, no brute-force, no load testing. Blind bugs are proven via out-of-band callbacks and canary tokens.
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
