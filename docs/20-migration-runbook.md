# Migration Runbook
# ProofScan → v4 Migration & Claude Code Execution Runbook (v2)

**Grounded in the actual repository structure. How to evolve the existing ProofScan repo into the v4 architecture (API-first + dual-mode) without disrupting the core, the frozen Scanner Contract, or the validated tools — and how to feed the current state into Claude Code so it builds correctly.**

*Supersedes runbook v1 · 2 October 2026*

---

## 0. What changed since runbook v1

Runbook v1 was written before the repository tree was inspected. The tree shows the project is **further along than v1 assumed**, so several v1 steps are now "already done — do not rebuild" rather than "build." This version is corrected against the real structure.

**Key correction:** the v4 "shared core" largely exists already. These are present in `core/` and MUST be extended, never regenerated:

| Already built in `core/` | What it is in v4 terms |
|---|---|
| `confidence.py` | Confidence engine (confidence separate from severity) |
| `correlation.py` + `assetgraph.py` | The substrate for attack-path chaining |
| `killswitch.py` | The v4 safety kill switch |
| `cost.py` | Per-scan cost tracking |
| `evidence.py`, `store.py`, `state.py` | Evidence store + finding store |
| `replay.py` | Record/replay |
| `measurement.py` | Accuracy/corpus harness |
| `registry.py`, `authz.py`, `ratelimit.py` | Scanner registry, ownership gate, rate limiting |

**The only genuinely new top-level directories are `api/` and `web/`.** Everything else is extension or configuration.

---

## 1. Guiding rule

> **Evolve in place. Never greenfield.** The core services, the four contract schemas, the three validated scanners, the corpus, and the ownership gate are KEPT. The v4 plan is layered on top. The single largest risk is Claude Code reading the new plan and rebuilding assets that already exist and already pass accuracy gates.

---

## 2. The repository as it stands (reference map)

```
Security-Platform/
├── CLAUDE.md                 # EXISTS — update it (Section 4), do not replace
├── contracts/                # FROZEN contract — 4 JSON schemas; extend via Stage A only
│   ├── evidence.schema.json
│   ├── finding.schema.json
│   ├── scanresult.schema.json
│   └── scanrun.schema.json
├── core/                     # KEEP + EXTEND — shared services (see table in Section 0)
├── scanners/                 # KEEP — domscout, email, tls (validated) + example. New engines added here.
├── cli/                      # KEEP — thin client over core; stays useful for testing/power users
├── corpus/                   # KEEP — ground-truth fixtures, generators, crosscheck, expected, results
├── config/                   # KEEP — authorised_scope, composition_rules, deprecation_calendar
├── tests/                    # KEEP + GROW — architecture, cli, contract, core, corpus, scanners, tools
├── tools/                    # KEEP — vendored testssl.sh (separate process), registry.yaml
├── docs/                     # 00–17 numbered + adr(02) + ledger(14) + archive/ + superpowers/
├── payloads/                 # EXISTS (reserved, empty) — payload library lands here
├── scripts/                  # authorise-domain.sh, scan-many.sh
├── docker-compose.yml, Makefile, pyproject.toml, uv.lock, SPEC.md
├── tools-and-features-list.md   # STALE strategy — archive it (Section 3)
└── temp/                     # pptx + screenshots — housekeeping only
```

**New directories this migration introduces:**
```
├── api/     # NEW (Stage B) — FastAPI layer wrapping core + scanners. The API-first contract.
└── web/     # NEW (Stage D) — React/TS dashboard, thin client over the API.
```

---

## 3. Pre-flight — hygiene, safety, and archiving the old strategy

Do all of this before feeding anything to Claude Code.

### 3.1 Branch & rollback safety
1. Resolve the dormant `tool-3-domscout` branch state — get to a clean, known `main` (domscout is present in the working copy; confirm it is merged, not stranded).
2. Commit/stash so the tree is clean.
3. `git tag pre-v4-migration && git push --tags` — guaranteed rollback point.
4. `git checkout -b migration/v4-architecture` — all migration work here; `main` stays shippable.
5. Confirm the full test suite is green — this is the regression anchor for the whole migration.

### 3.2 Repository hygiene
- Confirm `.gitignore` excludes `__pycache__/` and `*.pyc` (the tree is full of bytecode; committed bytecode causes churn during a refactor).
- Pin a single Python version — the tree shows both `cpython-312` and `cpython-313` artifacts; declare one in `pyproject.toml` so the API layer and CI test against one target.
- Confirm where CI is defined and that it runs (no `.github/` visible in the tree). CI is the regression gate during migration.

### 3.3 Archive the old strategy (critical for Claude Code)
The old "tool-first, no website until Phase 6" strategy directly contradicts the new API-first direction. If Claude Code reads both, it gets conflicting instructions and may follow the wrong one.

- Move `tools-and-features-list.md` (root) into `docs/archive/`.
- Confirm `docs/archive/tools-and-features-list-v2.md` is clearly archived (it already is).
- In every stale doc that states superseded strategy, add a one-line banner at the top: `> ARCHIVED — superseded by docs/18-v4-plan.md. Do not use for current direction.` This matters because Claude Code loads docs it reads; an un-banner'd stale file reads as current.

**Checkpoint:** clean `main`, rollback tag, migration branch, green tests, hygiene confirmed, old strategy archived with banners.

---

## 4. Feed the current state into Claude Code

Claude Code starts each session fresh. It carries knowledge through the project `CLAUDE.md` (loaded every session) and files you point it at. Set these up so every session already understands the repo's true state and the guardrails.

### 4.1 Add the new documentation in the repo's own numbering scheme
Do NOT create a separate `docs/plan/` folder — it fights the existing 00–17 convention. Add the new material as the next numbered docs:

- `docs/18-v4-plan.md` — the v4 plan (convert `Draft Plan.pdf` → markdown first; Claude reads markdown far more reliably and it diffs cleanly).
- `docs/19-v4-roadmap.md` — the development roadmap.
- `docs/20-migration-runbook.md` — this file.

Then record the pivot in the files the project already uses for that purpose:
- `docs/02-decisions.md` — add ADRs: "adopt API-first", "contract extension for offensive+chaining", "archive tool-first strategy".
- `docs/14-progress-ledger.md` — add a dated entry noting the v4 pivot and what it supersedes.
- `docs/03-roadmap.md` — add a banner pointing to `19-v4-roadmap.md` as the current roadmap.

### 4.2 Update the existing CLAUDE.md (do not replace it)
The repo already has a `CLAUDE.md`. Edit it. Keep it under ~200 lines (longer files reduce adherence). Add an explicit "extend, don't rebuild" section naming the already-built components. Suggested additions:

```markdown
## CURRENT STATE — read this before any structural work
This repo (ProofScan) is being evolved to the v4 architecture.
- Target & why:   docs/18-v4-plan.md
- Roadmap:        docs/19-v4-roadmap.md
- Migration plan: docs/20-migration-runbook.md
The old tool-first strategy in docs/archive/ is SUPERSEDED. Do not follow it.

## NON-NEGOTIABLE: extend, do not rebuild
These already exist in core/ and are validated. EXTEND them; never regenerate:
- core/confidence.py        (confidence engine)
- core/correlation.py       (chaining substrate)
- core/assetgraph.py        (asset graph)
- core/killswitch.py        (kill switch)
- core/cost.py              (cost tracking)
- core/evidence.py, store.py, state.py, replay.py, measurement.py
- core/registry.py, authz.py, ratelimit.py
The four files in contracts/ are the FROZEN Scanner Contract. Change them ONLY
as a deliberate, additive contract migration (Stage A), with an ADR, never ad hoc.
The three validated scanners (domscout, email, tls) must not be regenerated.
If a task seems to require rebuilding any of the above, STOP and ask.

## The only NEW top-level directories in this migration
- api/   FastAPI layer wrapping core + scanners (Stage B). API-first.
- web/   React dashboard, thin client over the API (Stage D).
No business logic in web/. The dashboard only shows what the API exposes.

## Hard rules (frozen — carried from existing ADRs)
- No exploitation of any kind.
- No active scan without verified ownership (core/authz.py, blocked by default).
- Licences: no Nmap/Nessus/Burp/TruffleHog/Semgrep rules; GPL only as separate
  process (testssl.sh stays vendored in tools/, run out-of-process).
- Never store customer secrets. Never say "compliant" (use "compliance readiness").
- Findings keep: evidence, confidence (separate from severity), state incl. inconclusive.

## Workflow
- Branch per task off migration/v4-architecture. PRs only; no direct commits to main.
- Dependencies via uv (pyproject.toml + uv.lock).
- Run the full test suite before every commit; the current passing baseline must hold.
- A bug is not fixed until a regression test exists that would have caught it.
- Follow the existing plan/spec workflow in docs/superpowers/ for new engines.
- Build/test commands: [fill in from Makefile]
```

### 4.3 Add path-scoped rules for the areas that need the most care
Use `.claude/rules/` with `paths:` frontmatter so a rule loads only when Claude touches those files (keeps CLAUDE.md short):

- `.claude/rules/contract.md` — `paths: ["contracts/**", "core/models.py"]` — "frozen contract; additive changes only, via Stage A, with an ADR; the schema-drift test must pass."
- `.claude/rules/core.md` — `paths: ["core/**"]` — "extend, never regenerate; these are validated services."
- `.claude/rules/api.md` — `paths: ["api/**"]` — "wrap existing scanners/core; never reimplement scan logic here."

### 4.4 Run /init, then verify
- Run `/init`. Because a `CLAUDE.md` already exists, it suggests improvements rather than overwriting. Accept the ones that capture real build/test commands and conventions.
- Run `/context` and confirm your `CLAUDE.md` and the `.claude/rules/` files appear under **Memory files**. If they are missing, Claude cannot see them — fix before proceeding.

**Checkpoint:** new docs added in-scheme, old strategy archived + bannered, CLAUDE.md enforces extend-don't-rebuild, rules in place, `/context` confirms everything loads.

---

## 5. Migration sequence — precise order, each stage shippable & reversible

Each stage is one or more PRs on `migration/v4-architecture`. Do not begin a stage until the previous one is merged and green.

### Stage 0 — Close Phase 1 first
Finish **Tool 4 (Web Light + AI exposure)** — the one Phase-1 item still owed. Close Phase 1 before re-architecting around it, so the API wraps a complete defensive set.

### Stage A — Contract extension (one deliberate migration)
The v4 plan needs the contract to express:
- **attack-path linkage** — findings referencing each other to form chains (builds on `correlation.py`/`assetgraph.py`).
- **state-affecting fields** — for the offensive/race class: what state changed + cleanup info.
- **mode / vantage tags** — defensive vs offensive; unauth / auth / agent.

Execute precisely:
1. Add new **optional** fields to `contracts/finding.schema.json` (+ others as needed) so existing findings stay valid.
2. Mirror them in `core/models.py`.
3. Keep `tests/contract/test_schema_model_drift.py` green — it is your guard.
4. Write an ADR in `docs/02-decisions.md`.

This goes first because everything downstream depends on the contract being right. Give it the most review.

### Stage B — API layer over existing tools (the API-first pivot)
1. Create `api/` (FastAPI, added via `uv`).
2. Endpoints wrap the **three existing scanners** and `core/` services: launch scan, scan status, list findings (with evidence + confidence), fetch report. Reuse `core/registry.py` to enumerate scanners.
3. **No new scanning logic** — this stage only exposes what already works.
4. The auto-generated OpenAPI spec becomes the contract the dashboard consumes.

**Milestone:** the three validated tools run via API and return the same gate-passing results they produce via the CLI.

### Stage C — Compliance foundations (cannot be retrofitted)
- One-year retention + India-resident storage + tiered (hot/cold).
- Internal access-control model (zero standing access, break-glass, immutable audit).
- Own-breach runbook (CERT-In 6h / DPDP 72h).
Note: `core/killswitch.py` and `core/cost.py` already exist — wire them into the API, don't rebuild.

### Stage D — Dashboard v1 (thin client + coming-soon)
1. Create `web/` (React + TypeScript + Tailwind/shadcn).
2. Screens: login, scan launch, live progress, findings + evidence, report, and the **roadmap/coming-soon grid**.
3. Every not-yet-built capability is an honest "coming soon" tile.

**Milestone:** end-to-end in the browser — sign up → verify → scan → report.

### Stage E onward — new engines as modules
Authorization/RBAC → concurrency → firewall → agent → IoT. Each is a **new scanner under `scanners/` implementing the existing contract**, registered via `core/registry.py`, exposed via `api/`, surfaced as a dashboard tile that flips from "coming soon" to live. Follow the existing `docs/how-to-add-a-scanner.md` and the `docs/superpowers/` plan+spec workflow.

---

## 6. Driving Claude Code through each stage

### 6.1 Use plan mode for anything structural
Start each stage in **plan mode**: Claude proposes a plan and waits for approval before editing. Review it against "extend, don't rebuild" before letting it write. This is the main guard against an over-eager refactor.

### 6.2 Small, reviewed PRs
One task = one branch = one PR. Never let a single session rewrite large areas unattended — large diffs hide a silent core rewrite.

### 6.3 Safe prompt template (adapt per stage)
```
Read @docs/18-v4-plan.md, @docs/19-v4-roadmap.md, and @docs/20-migration-runbook.md.

We are on Stage B. Do ONLY Stage B: create api/ (FastAPI) that wraps the THREE
EXISTING scanners (domscout, email, tls) and core/ services via core/registry.py.
Do NOT modify scanner logic. Do NOT touch core/ except to import it.
Do NOT rebuild anything listed under "extend, don't rebuild" in CLAUDE.md.
Propose a plan first; wait for my approval before writing.
```
Habits: name the stage and say "only this stage"; say what NOT to touch; ask for a plan first; after changes, "run the full suite; the baseline must still pass."

### 6.4 Record decisions as ADRs
Have Claude write an ADR in `docs/02-decisions.md` for each structural decision. The project's ADR + ledger discipline is a strength — keep it.

### 6.5 Verify context every session
Run `/context` at the start of each session. If a session seems to "forget" extend-don't-rebuild, the file didn't load — fix before continuing.

---

## 7. Guardrails vs the classic failure modes

| Risk | Guard |
|---|---|
| Claude rebuilds an existing core service | CLAUDE.md extend-don't-rebuild list + `.claude/rules/core.md` + plan mode |
| Claude follows the old tool-first strategy | Old docs archived + bannered; CLAUDE.md names current docs |
| Contract drifts via ad-hoc edits | One Stage-A migration + ADR + `test_schema_model_drift.py` |
| A refactor breaks a validated tool | Test baseline must pass before every commit; scanners have gate tests |
| Compliance bolted on too late | Stage C is mandatory, not deferred |
| Dashboard scope creep | API-first: `web/` can only show what `api/` exposes |
| Silent large rewrite in one session | Branch-per-task, PR review, plan mode |
| Lost rollback point | `pre-v4-migration` tag; `main` stays shippable |

---

## 8. Definition of done for the migration

- Tool 4 complete; Phase 1 closed.
- Contract supports attack-path linkage + state-affecting + mode/vantage (Stage A); drift test green.
- The three validated tools run via the **API** with their gate-passing results (Stage B).
- **Compliance foundations** in place (Stage C).
- **Dashboard v1** shows a real scan end-to-end with coming-soon tiles (Stage D).
- Test baseline still passes, plus new tests for the API and compliance layers.
- `main` shippable; the CLI still works.

From here, Phase-2+ engines are added as modules on the stable foundation.

---

## Quick-start checklist

- [ ] Resolve domscout branch; clean `main`; tag `pre-v4-migration`; branch `migration/v4-architecture`
- [ ] Fix `.gitignore`/Python-pin; confirm CI
- [ ] Archive `tools-and-features-list.md` + add ARCHIVED banners to stale docs
- [ ] Convert Draft Plan PDF → `docs/18-v4-plan.md`; add `19-v4-roadmap.md`, `20-migration-runbook.md`
- [ ] Add ADRs to `docs/02-decisions.md`; ledger entry in `docs/14-progress-ledger.md`
- [ ] Update `CLAUDE.md` with extend-don't-rebuild + current-docs pointers; add `.claude/rules/`
- [ ] `/init`; verify with `/context`
- [ ] Stage 0: finish Tool 4
- [ ] Stage A: contract extension (+ ADR, drift test green)
- [ ] Stage B: api/ over the 3 validated tools
- [ ] Stage C: compliance foundations
- [ ] Stage D: web/ dashboard v1 + coming-soon
- [ ] Stage E+: new engines as modules

---

*Runbook v2, corrected against the actual repository tree. Claude Code behaviours (CLAUDE.md load, /init suggest-not-overwrite, @-imports, path-scoped rules, plan mode, /context) reflect current documentation as of 2 October 2026; confirm exact commands in your installed version with /help.*