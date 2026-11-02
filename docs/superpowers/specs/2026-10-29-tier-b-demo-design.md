# Tier-B demo — the first two host findings on a lab box — Design

> **Status:** DRAFT for operator approval. Nothing is built until this is approved (brainstorming
> HARD-GATE). This is a **scoped slice** of the approved host-agent design
> (`docs/superpowers/specs/2026-10-13-host-agent-design.md`) and plan
> (`docs/superpowers/plans/2026-10-13-host-agent.md`), not a replacement for either. Where this
> document and the parent spec disagree, the parent spec wins and this slice is wrong.

## 1. Intent, and the why

A small, honest, end-to-end demo: point the read-only host collector at a deliberately
misconfigured Ubuntu box, copy the snapshot it writes to the platform, and watch two findings come
out through the existing pipeline — each with a control-vs-test evidence pair, calibrated
confidence, and a receipt line naming the exact command behind it.

**Why these two findings (operator, this session):**

1. **Root SSH login enabled** — universally legible as "obviously bad", the cheapest possible
   collection, and the anchor that makes the demo readable to a non-specialist.
2. **Pending reboot — a newer kernel is installed than the one running** — chosen deliberately as the
   second beat, because it is a thing an *external* scan physically cannot see. It is the one-line
   case for why an agent exists at all.

**Why now:** the four customer scanners already demo (Tier A). This is the first demo of something
*new* since they shipped, and the first exercise of the `agent/` → `host`-scanner pipeline the whole
Alpha agent track is built on. Getting this slice right de-risks Steps 4–5.

## 2. Goals

- A real snapshot, **recorded** from a real lab box (ADR-027; never hand-written), produces exactly
  two findings through `scan run host --snapshot <file>`.
- Each finding cites its snapshot section and the receipt line that produced it (spec §9).
- A **clean container** produces neither finding — a genuine negative, not the positive box with the
  finding unnoticed (docs/26 Step 3's explicit warning).
- The demo runs from the repo: `scan run host --snapshot <recorded-fixture>` reproduces the findings
  deterministically, and `make corpus` gates `host` on real numbers with its claim count stated.

## 3. Non-goals (this slice only — all are in the parent plan, just not here)

- **No packages/vulnerability matcher** (parent plan D2-full, F4). Pending-reboot needs kernel
  *package names and versions* from `dpkg`, **not** the distro security-data matcher. This keeps the
  slice entirely clear of the blocked vulnerability-data licence (D87/§7) and of D95.
- **No network path.** The collector writes a file; the operator copies it; the platform ingests the
  file. The `core.addresses.LAB_NETWORKS` widening and its reviewed `core/` change are **not** on
  this slice's path — they belong to the later external-scanner/correlation demo.
- **No distribution-agnostic collector (D95).** One distribution: Ubuntu 22.04. The collector is
  written to the parent spec's allowlist discipline, but proven on one distro only.
- **No listener, no upload, no always-on agent, no signing.** All post-Alpha per spec §10.
- **No module 4 correlation, no fleet view.** A later tier.

## 4. Anti-goals (what makes this a failure even if it "works")

- A finding that cannot be traced to something present in the snapshot (D28/D31/D67/D94 — "a check
  that cannot fail"). The negative must be able to fail the positive's check.
- A collection error that reads as "clean". A missing or errored section must surface as a scan error
  or a reason-bearing `inconclusive`, never a pass (R1/R2).
- Any secret value in the snapshot bytes, error paths included (hard constraint 5; parent spec §6).
- `confirmed` claimed for either finding. Neither has an independent second method under §5.1, so
  both cap honestly below `confirmed` (see §7).

## 5. Inherited constraints (not restated — pointers to the parent spec)

All of the parent plan's **Global constraints** and **Review focus** apply unchanged: `agent/` is
stdlib-only and imports nothing from `core/`/`contracts/`; 3.6 syntax floor in one constant;
`shell=False`, argv-only, fixed binary dirs, scrubbed env; ADR-004 read-only, absolute; no snapshot
value is ever used as a path/arg/format string, and in reverse the snapshot is **hostile input** on
the platform side (spec §13). The snapshot format is spec §4 verbatim (manifest/sections cannot
disagree; `status ∈ collected|unavailable|error`; named `counts`; `self_hash` = corruption
detection, **not** tamper-evidence).

## 6. The decided "how" — the slice selection and ordering

### 6.1 Prerequisites that are not "collector code"

| # | Prereq | Why it blocks | Owner |
|---|---|---|---|
| P1 | Land PR #68 (agent direction refinement) | current branch; docs only | me → operator merges |
| P2 | **A6 — the evidence-contract migration** (its own ADR + independent review) | parent plan: *"Blocks Phase B: nothing may construct evidence before this lands."* Both findings produce `command_output`/`file_excerpt` evidence (spec §12.3/§12.4), which do **not** yet exist in `contracts/`. | me |
| P3 | domscout corpus regeneration (D67) | scheduled before `host` records its first fixtures, so a new-vs-drift diff stays attributable | me |
| P4 | Lab boxes stood up: **misconfigured VMware VM** (positive) + **clean Ubuntu container** (negative) | the reboot state cannot exist in a container (shared kernel, docs/26 Step 3) | **operator** |

For the A6 migration, this slice needs only the two evidence kinds its findings use:
`command_output` (spec §12.3) and `file_excerpt` (spec §12.4). `access_matrix` (§12.5, module 8) and
the `Telemetry.counts` fold-in (§12.6, D65) are part of the *same* migration in the parent plan;
A6 is one migration and lands whole — this slice does not get to ship a half-migration. So A6 is
built to the parent plan's A6 in full; this document only records which parts the demo *exercises*.

### 6.2 The lab box (Step 3, scoped to the demo)

- **Positive — VMware VM, Ubuntu 22.04, purpose-built, never a production machine, not on this
  server, discardable.** Two deliberate misconfigurations:
  - `PermitRootLogin yes` in `/etc/ssh/sshd_config`.
  - A newer kernel package installed with **no reboot**, so `uname -r` (running) is older than the
    newest installed kernel package.
- **Negatives — two, because the two findings have different negative needs:**
  - **SSH negative — a clean Ubuntu 22.04 container:** `PermitRootLogin prohibit-password` (or
    absent, so the distro default applies). A container is a valid negative here; `sshd` config is
    on disk.
  - **Reboot negative — a VM in a clean state** (running kernel == newest installed kernel). A
    container **cannot** serve this: it shares the host kernel, so `uname -r` reports the host's
    kernel, unrelated to the image's kernel packages. Against a container the reboot check is
    `not_applicable` by design (the box has no kernel of its own) — worth a small corpus case, but
    not the clean negative the gate needs. **Decided (operator, 2026-10-29): a clean-state snapshot
    of the same VM, recorded before the extra kernel is installed and before root login is enabled —
    the "flip one box" caveat is recorded in the corpus case, and a separate clean box is the
    follow-up when this reaches the real fleet gate.**
- Both registered per Step 3's rules (VulnHub conditions do not apply — these are our own boxes).
  A snapshot is recorded from **each** (ADR-027). Per D67, if the demo later needs a "could not read
  sshd config" case, that case's snapshot must **contain** the `ssh` section with status `error`,
  not omit it.

### 6.3 Collector slice (`agent/`, parent plan Phases B, C, and a subset of D)

- **Phase B** in full: `snapshot.py` (manifest/sections/counts/`self_hash`), the 3.6-floor and
  stdlib-only tests, the entry shim + unsupported-runtime snapshot, `redact.py` as a superset of
  `core/redaction.py`.
- **Phase C** in full: `allowlist.py`, `run.py` (argv-only runner), `readfile.py`, and the receipt
  assembled as they run.
- **Phase D, subset:**
  - **D1** — `os_release`, `kernel` (running kernel string; the mechanism for "installed kernels"
    comes from D2's dpkg read), host identity (hostname, machine-id **fingerprint**).
  - **D2, kernel-only slice** — `packages` via `dpkg`, names and versions only. The demo reads this
    section **solely** to find the newest installed kernel package; no security-data matching touches
    it. (The collector still records the full package section honestly; the *scanner* only judges the
    kernel packages in this slice.)
  - **D4** — `ssh` config keys (via the allowlisted effective-config read), enough for
    `PermitRootLogin`.
  - **D5** — the "modules judge nothing" grep test applies to every module written.
- **Phase E** in full: the canary minimisation proof, determinism test, `--explain`, `--explain-plan`.
  These are the discipline that gets an agent accepted onto a fleet and are not deferred.

### 6.4 `host` scanner slice (`scanners/host/`, parent plan Phase F subset)

- **F1 / F1b / F1c** in full: snapshot reader with every failure a scan error; hostile-input
  pre-parse limits and no-value-becomes-a-path; output encoding at every render boundary with the
  planted-payload test. These are non-negotiable even for a demo — the snapshot is still hostile
  input.
- **F2** — the two checks, over `collected` sections only; an `error`/`unavailable` section →
  `inconclusive` **naming the reason**, never a pass:
  - `host-ssh-root-login`: effective `sshd` config shows root login permitted. Control-vs-test: the
    allowlist entry's declared expectation (`prohibit-password`/`no`) vs what the snapshot holds.
  - `host-kernel-reboot-pending`: newest installed kernel package version > running kernel version.
    Control-vs-test: running vs installed, both from the snapshot, with `collected_at` and clock skew
    stated (spec §4 — no wall-clock arithmetic). When the snapshot shows the box shares a kernel it
    does not own (a container, `kernel_ownership` `shared` or `unknown`), this check returns
    `inconclusive` with a reason naming the shared kernel — never a pass and never a spurious
    positive. (Decided 2026-10-29: ADR-032 closes the `not_applicable` reason set to
    `special-use-name`; a true `not_applicable: shared-kernel` would need an ADR-032 amendment and a
    `core/` review, out of demo scope. `inconclusive` naming the reason is the honest, in-scope
    state.)
- **F3** — evidence: each finding cites its section and receipt line; `detection_methods[]` with
  honest single-method independence classes (spec §9).
- **F4 is explicitly excluded** (the distro security matcher, gated on A2's licence sign-off).

### 6.5 State ceilings — decided, and honest (spec §9)

- `host-kernel-reboot-pending` is a **package finding**: one package-database reading is one
  observation, so it caps at **`highly_likely`**. `confirmed` is not reachable in Alpha and this slice
  does not pretend otherwise.
- `host-ssh-root-login` rests on a single reading of the effective config — one method — so it too
  does not reach `confirmed`. `state` is computed by `core/state.py`; neither check hand-sets it.

### 6.6 Corpus and gate (parent plan Phase G)

- Snapshots recorded from the VM (positive) and the container (negative), committed as fixtures.
- A negative per positive; the D67 harness assertion that every asserted outcome is traceable to
  something present in the artefact.
- The gate's three numbers **with its claim count** recorded in `SPEC.md`; until the gate exists,
  `host` stays PLANNED with no figure.

## 7. What is left to the builder

- The `scan run host --target <hostname> --snapshot <file>` ingest path (spec §9): `--snapshot` is a
  **new CLI flag added in this slice**, and the corpus harness must learn to drive a file-ingest
  scanner (the other scanners scan live or `--replay`; `host` reads a recorded snapshot fixture).
  The hostname is carried per spec §9. Builder's to wire, to the existing `core/registry.py` pattern.
- Exact allowlist entries (binary paths, argv templates, timeouts, caps, `reason_id`s) for the SSH
  effective-config read and the `dpkg`/kernel reads — to the parent spec §5 pattern. The builder
  settles the specific argv; the *rule* (no derived arguments, fixed binary dirs) is fixed here.
- The precise kernel-version comparison (Ubuntu package version ordering vs `uname -r`) — a real
  correctness question the builder resolves with tests against recorded snapshots, not assumptions.
- Fixture file layout under `corpus/fixtures/host/` consistent with the other scanners.
- Whether the clean container also supplies a package-only negative, or a second clean snapshot is
  recorded — builder's call, as long as every positive has a traceable negative.

## 8. Decisions taken in review

- **The reboot finding's negative** (§6.2) — **decided (b), 2026-10-29:** a clean-state snapshot of
  the same VM, recorded before the extra kernel is installed and before root login is enabled. The
  "flip one box" caveat lives in the corpus case; a separate clean box is the follow-up at the real
  fleet gate. This changes only what the operator records, not what is built.

## 9. Open items carried in, not resolved here

- **A5 fleet-probe results** (OS/Python mix, the 3.6 floor) — not needed for a single-distro demo;
  the floor stays a stated assumption. Carried.
- **D95 distribution-agnostic strategy** — deferred; this slice is one distro by design.
- **Debian data licence (D87/§7)** — not touched; this slice has no vulnerability-data path.
- **Signing (docs/23 item 7)** — out, per spec §10. `self_hash` is corruption detection only.
