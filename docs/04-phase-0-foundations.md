# 04 — Phase 0: Foundations

*Before tool #1. Nothing here is user-visible; all of it is what stops the tool-first strategy producing an unmergeable pile.*

> **Re-estimated 1–2 weeks → 3–4 weeks (v3.1).** The original figure was optimistic for a list that quietly contains a full CI pipeline, a dual-source-of-truth schema, a rate limiter with adaptive backoff, a confidence engine, and a corpus harness with docker-composed vulnerable targets. Three decisions previously left to the implementer are now made below.

**Exit criterion:** `scan example --target example.com --mode light --out r.json` produces schema-valid JSON, `make corpus` reports precision, recall and inconclusive rate for it, and CI fails if any regresses.

---

## Task list

### 0.1 — Repository and toolchain

- [ ] `git init`; the repo is not yet under version control
- [ ] Python 3.12+, dependency management via `uv` or Poetry, lockfile committed
- [ ] `ruff` (lint + format), `mypy --strict` on `core/`, `pytest`
- [ ] `Makefile`: `make install`, `make test`, `make lint`, `make corpus`, `make scan`
- [ ] CI (GitHub Actions): lint, typecheck, unit tests, corpus run, licence check
- [ ] `.env.example` documenting every config key; secrets never committed

**Directory layout:** exactly as specified in [01-architecture.md](01-architecture.md#repository-layout). Create the empty structure now, including `contracts/`, `core/`, `scanners/`, `corpus/`, `payloads/`, `tools/`, `cli/`, `tests/`.

---

### 0.2 — The Scanner Contract *(the critical task)*

Do this before anything else in `core/`. Everything depends on it, and changing it later means migrating every scanner and every stored finding.

- [ ] `contracts/finding.schema.json` — JSON Schema for a finding, exactly as specified in [01-architecture.md](01-architecture.md#the-finding-model)
- [ ] `contracts/evidence.schema.json` — the evidence kinds and their shapes
- [ ] `contracts/scanresult.schema.json` — findings + telemetry + errors + scan metadata
- [ ] `core/models.py` — typed Python objects (pydantic), validated against the schemas in tests so the two can never drift
- [ ] `core/scanner.py` — `BaseScanner` with `name`, `version`, `supported_modes`, `target_types`, `validate()`, `run()`
- [ ] `core/registry.py` — decorator-based registration, `get_scanner(name)`
- [ ] `ScanContext` — carries rate limiter, kill switch, HTTP client, DNS client, OOB client (stub for now), progress reporter, cost meter, authorised scope

**Design checks before freezing.** Write these as tests — they are the contract's acceptance criteria.

1. Can a finding express "we tried and could not tell"? (`state: inconclusive`) → must be yes
2. Can evidence express a control-vs-test pair, **including for `oob_callback` and `timing`**, which are not request/response pairs? → must be yes
3. Can a finding be traced to the **list** of contributing detection methods with their independence classes, and to the payload that produced it? → must be yes, or the calibration dataset is worthless
4. Does every finding have a deterministic `id` that survives re-scans, **including a location-less finding (`location: "$"`) and two instances of one check at one location (`instance_key`)**? → must be yes
5. **Is the scan-error vs `inconclusive`-finding boundary enforced?** A scanner that cannot execute at all produces zero findings and an `errors[]` entry; a check that ran but reached no verdict emits an `inconclusive` finding and is never silently omitted. → must be yes

**Three decisions the plan previously left to the implementer, now made:**

- **Schema/model drift.** JSON Schema in `contracts/` is authoritative. `core/models.py` is pydantic, and a test round-trips every schema example through the models and back, failing on any divergence. Codegen is not used — it obscures where the truth lives.
- **`scanner_version` bump policy.** Patch = no result change (refactor, logging). Minor = same checks, better detection (a fixed parser, a new evidence field) — findings keep their IDs. Major = a check changed *meaning*, which is a `check_id` rename plus a `renamed_from` entry, not a silent redefinition. Worked example: tightening the SPF lookup counter so it stops counting `ip4:` is **minor**; changing `spf-too-permissive` to also fire on `~all` is a **new check_id**, because a stored finding's meaning would otherwise shift underneath its ID.
- **Authorised-scope file schema.** Specified in [09-ownership-verification.md](09-ownership-verification.md).

---

### 0.3 — Core services

Every one of these exists in `core/` and nowhere else. A scanner that constructs its own HTTP client is a bug, and CI should catch it.

- [ ] **`core/http.py`** — the single HTTP client. Enforces rate limits, sets our user agent, records every request/response pair for evidence, honours the kill switch between requests, refuses out-of-scope hosts, does not follow redirects that leave scope, caps body size.
- [ ] **`core/dns.py`** — the single DNS client. Caching, timeouts, retry, and the same scope check.
- [ ] **`core/ratelimit.py`** — per-host token bucket, adaptive backoff on rising latency / 429 / 503, global concurrency cap per target organisation.
- [ ] **`core/killswitch.py`** — three levels (one scan / one customer / everything), checked **between every request**, not just between phases. In-process now; backed by shared state in Phase 6.
- [ ] **`core/authz.py`** — scope enforcement. Given a target and an authorised scope, is this request allowed? **Deny by default.** Light mode needs no authorisation; Standard and Deep require a valid, unexpired, unrevoked `authz_ref`. Until Phase 6 the scope comes from `config/authorised_scope.yaml` — schema and rules in [09-ownership-verification.md](09-ownership-verification.md).
- [ ] **`core/evidence.py`** — capture, **redact at capture time** (cookies, `authorization`, anything matching a secret pattern), truncate large bodies with explicit markers, serialise to the schema, export as curl.
- [ ] **`core/confidence.py`** — the log-odds combination from [01-architecture.md](01-architecture.md#the-confidence-engine), collapsing methods that share an `independence_class` before combining. Hand-assigned priors for now; `calibrate()` is the identity function until Phase 4, bucketed per (scanner × detection_method), never per `check_id`. Emitted values carry `confidence_provisional: true`.
- [ ] **`core/state.py`** — the state-derivation truth table from [01-architecture.md](01-architecture.md). State is **computed, never hand-set by a scanner**. Unit-test every row of the table.
- [ ] **`core/cost.py`** — count requests, wall time, and (later) AI tokens per scan. Start now; without it we will not know our margins until it is too late to fix them.

---

### 0.4 — The CLI

- [ ] `scan <tool> --target <t> --mode light|standard|deep --out result.json`
- [ ] `scan list` — registered scanners, versions, supported modes
- [ ] `--format json|table` — table for humans while iterating
- [ ] `--record <dir>` / `--replay <dir>` — capture real traffic once, replay it offline forever. **This is what makes corpus tests deterministic and fast.** Build it now, not later.
- [ ] Progress to stderr, results to stdout, so output pipes cleanly
- [ ] Exit codes: 0 = ran, 1 = error, 2 = ran but findings above a `--fail-on` severity (for CI use later)

---

### 0.5 — The corpus harness

This is what "check verify is that giving exact results how we want" becomes in practice.

- [ ] `corpus/targets/<scanner>.yaml` — target definitions: what to scan, in which mode, and which corpus tier (vulnerable / known-good / frozen)
- [ ] `corpus/expected/<scanner>.yaml` — the known-correct answers, as a set of `check_id` + `location` pairs
- [ ] `corpus/fixtures/` — recorded traffic for offline replay
- [ ] `make corpus` — runs every scanner against its corpus, computes **precision, recall, F1 per scanner and per check_id**, prints a table
- [ ] Writes `corpus/results/latest.json`; CI compares against the committed baseline and **fails on any precision regression**
- [ ] Reports **precision, recall and inconclusive rate**, per [10-measurement.md](10-measurement.md) — not raw counts
- [ ] Local docker-compose bringing up the vulnerable targets: OWASP Juice Shop, DVWA, VAmPI. `badssl.com` and our own fixtures cover TLS. **The benchmark tier (OWASP Benchmark, WAVSEP) can be deferred to Phase 2** — it only matters once the Website Scanner exists — but wire the tier concept in now.
- [ ] At least one **known-good** target per scanner. Anything reported there is a false positive by definition.

---

### 0.6 — Tool registry and licence enforcement

Build this in week one. Retrofitting it is painful, and it is the artefact a legal review will ask for.

- [ ] `tools/registry.yaml` — for every third-party binary or library: name, version (pinned exactly), licence, SPDX identifier, source URL, what we use it for, isolation mode (`library` / `subprocess`), sign-off status and date
- [ ] `tools/` holds pinned binaries or a script that fetches them by checksum
- [ ] **CI licence check** — fail the build if a dependency appears with a licence not on the approved list ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves))
- [ ] **CI GPL isolation check** — fail if anything marked GPL in the registry is declared as `library` rather than `subprocess`. This is the automated half of the rule that nobody accidentally links GPL code into our binary.

---

### 0.7 — The reference scanner

- [ ] `scanners/example/` — a deliberately trivial scanner (e.g. "does this domain resolve, and does it have an A record") that exercises the entire loop: registry → context → DNS client → finding → evidence → confidence → schema validation → CLI output → corpus scoring
- [ ] Its corpus entries include one positive, one negative, and one deliberately unresolvable target that must produce `inconclusive` rather than an error
- [ ] `docs/` snippet: "how to add a new scanner", written by doing this one

---

## What is explicitly NOT in Phase 0

- Anything the Website Scanner needs (crawler, browser orchestration, payload execution)
- The benchmark corpus tier — deferred to Phase 2, when it has a consumer
- The OOB client beyond a stub that raises
- Any calibration logic beyond the identity function

## Sequencing

```
0.1 repo ──▶ 0.2 CONTRACT ──▶ 0.3 core services ──▶ 0.4 CLI ──▶ 0.7 reference scanner
                    │                                              │
                    └──────────▶ 0.5 corpus harness ───────────────┘
             0.6 tool registry (parallel, any time in week one)
```

**Do not parallelise 0.2.** Everything downstream encodes its assumptions.

---

## Definition of done

- [ ] `make test` green, `make lint` green, `mypy --strict core/` clean
- [ ] `scan example --target example.com --mode light` → schema-valid JSON
- [ ] `make corpus` → a precision/recall table including the example scanner
- [ ] CI fails on a deliberately-introduced false positive in the example scanner (verify this by actually breaking it once)
- [ ] `tools/registry.yaml` exists with every current dependency and a licence for each
- [ ] "How to add a new scanner" is written and someone other than the author can follow it
- [ ] `config/authorised_scope.yaml` exists, `core/authz.py` denies Standard mode for a target absent from it, and there is a test proving it
- [ ] Every row of the state-derivation truth table has a unit test

---

## Notes for later

- The kill switch is in-process now. Phase 6 needs it backed by shared state (Redis or a database flag) so it works across workers. The interface should not change.
- `core/authz.py` reads an allowlist file now and a database in Phase 6. Same interface.
- The OOB client in `ScanContext` is a stub that raises. Phase 2a implements it. Scanners written before then must handle its absence by returning `inconclusive`, not by crashing — write that test now.
