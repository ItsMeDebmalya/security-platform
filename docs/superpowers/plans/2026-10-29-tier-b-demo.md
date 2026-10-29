# Tier-B Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. **Nothing starts until the operator approves this plan**
> (his standing rule for D59/D60/the lab entry point).

**Goal:** a recorded snapshot from a deliberately-misconfigured Ubuntu lab box produces exactly two
findings — `host-ssh-root-login` and `host-kernel-reboot-pending` — through `scan run host
--snapshot <file>`, each with a control-vs-test pair and a receipt line, with a clean-state snapshot
producing neither, gated in `make corpus`.

**Architecture:** read-only collector in `agent/` writes one versioned snapshot per host; a platform
`host` scanner turns the snapshot into findings on the frozen contract. The collector judges
nothing; the scanner collects nothing. The snapshot is to the `host` scanner what a fixture
directory is to `--replay`, and it is treated as **hostile input** on the platform side.

**Tech Stack:** Python 3.13 on the platform (`core/`, `scanners/`, `cli/`, `pytest`, `uv`);
stdlib-only Python at a 3.6 syntax floor inside `agent/`.

**Spec:** `docs/superpowers/specs/2026-10-29-tier-b-demo-design.md` (this slice), which is a scoped
subset of `docs/superpowers/specs/2026-10-13-host-agent-design.md` (the parent spec) and
`docs/superpowers/plans/2026-10-13-host-agent.md` (the parent plan). **Executors read all three.**
Where this plan and the parent disagree, the parent wins.

## Global Constraints

Copied from the parent plan's Global constraints — every task's requirements implicitly include
these:

- `agent/` imports the standard library and `agent/` only — never `core/`, `contracts/`, `scanners/`.
  Enforced by a test.
- **Python 3.6 syntax floor inside `agent/`**, enforced by `ast.parse(..., feature_version=(3, 6))`
  over every `agent/` file; the floor lives in **one** constant. `UP` must not rewrite `agent/` to
  3.9+ syntax (per-directory ruff config, reason in the config).
- No new runtime dependency anywhere; no build step for the collector (plain `.py` run by host
  `python3`).
- `shell=False` always; argv lists only; binaries from a fixed directory list, never `PATH`; a
  scrubbed fixed environment.
- **ADR-004 absolute:** the collector reads. No write, install, service control, or network call. A
  verb outside the read-only set is inexpressible in the allowlist; a test asserts it.
- Hard constraint 5: no secret value in the snapshot or receipt, redacted at capture.
- Every count says what it counted (D64); no conflated total; no field named `requests` in the
  snapshot (D65).
- Scanner `name = "host"`, `version = "0.1.0"`, `target_types = {"host"}`, `vantage: agent`,
  `engagement: defensive` (ADR-034). `state` never hand-set.
- **No value received from a host is ever used as a path, filename, command argument, URL, SQL
  identifier or format string** (spec §13.2), and in reverse the snapshot is hostile input (§13).
- Line length 100; ruff `E,F,I,UP,B,SIM,N,RUF`; mypy strict. Commit trailer per the active session;
  `.claude/` never staged.
- Corpus fixtures come only from real recordings (ADR-027); a snapshot from a real lab box is the
  recording.
- `confirmed` is unreachable for both findings in Alpha (spec §9): package findings cap at
  `highly_likely`; the SSH finding rests on one method.

## Review Focus

The input classes the spec implies that each own a task's tests (parent plan Review Focus, scoped to
this slice):

1. **A section that silently disappears** → scan error, never a clear report (R1). Owned by Task 6 (F1).
2. **A command that fails mid-run** (non-zero exit, timeout, missing binary, oversized output) →
   `status: error` with the reason, in section and receipt (R2). Owned by Task 3 (C2).
3. **A secret on an error path** — a parse failure must not quote the failing line; a refused path
   must not echo content. Canary test on raw bytes, errors included. Owned by Task 5 (E1).
4. **The allowlist as a shell** — no argument from collected data; no `PATH` resolution; no symlink
   escape. Owned by Task 2 (C1) and Task 3 (C2/C3).
5. **A hostile snapshot** — pre-parse limits refuse (never truncate); no snapshot value becomes a
   path/arg/format string; planted payloads inert and **present** in every render boundary. Owned by
   Task 6 (F1b/F1c).

---

## Task 1: A6 — the evidence-contract migration

**This is the hard prerequisite for everything below** (parent plan: *"Blocks Phase B: nothing may
construct evidence before this lands"*). It touches frozen `contracts/`, so it is **its own ADR and
its own reviewed PR**, to the `core/` review bar or higher.

**Authority:** execute parent plan task **A6** in full (parent spec §12). It lands as one whole
migration — `command_output` (§12.3), `file_excerpt` moved out of `reserved` and specified (§12.4),
`access_matrix` (§12.5), and `Telemetry.counts` alongside an unchanged `requests` (§12.6, D65). This
demo *exercises* only `command_output` and `file_excerpt`, but the migration is not shipped half-done.

**Files:**
- Create: `docs/02-decisions.md` (new ADR, next free number), `docs/08-changelog.md` entry.
- Modify: `contracts/evidence.schema.json`, the evidence models, `contracts/` drift fixtures.
- Test: the conformance/round-trip tests named in parent A6.

- [ ] **Step 1:** Write the failing conformance tests **before** the schema change (parent A6): one
      case per new kind; a case that every kind rejects evidence with no `receipt_ref`; a round-trip
      proving no artefact valid today becomes invalid; a case that `requests` still equals what it
      equalled before.
- [ ] **Step 2:** Run them; expect FAIL (kinds not defined).
- [ ] **Step 3:** Write the ADR (the migration's rules, §12.7) and apply the additive schema +
      model change.
- [ ] **Step 4:** Run the contract drift test and the Step-1 tests; expect PASS; confirm existing
      corpus baselines unchanged.
- [ ] **Step 5:** Commit. **Independent review before merge** (contracts/ bar).

**Exit:** evidence can carry `command_output` and `file_excerpt`; no artefact valid today is now
invalid. **Do not start Task 2 until this is merged.**

---

## Task 2: Collector snapshot format + floor + runtime gate + redaction (parent Phase B)

**Authority:** execute parent plan tasks **B1, B2, B2b, B3** as written. No demo-specific delta —
the snapshot format (spec §4), the 3.6-floor and stdlib-only tests, the unsupported-runtime shim,
and `agent/redact.py` (a superset of `core/redaction.py`) are needed whole.

**Files:** Create `agent/snapshot.py`, `agent/__main__.py`, `agent/redact.py`, `agent/version.py`
(the single floor constant); Test under `tests/agent/`.

**Produces (for later tasks):** `snapshot.build(manifest, sections, counts) -> dict` and the
`self_hash` procedure (B1); the stdlib-only + floor tests that guard every later `agent/` file (B2);
the unsupported-runtime snapshot shape (B2b) that Task 6/F1 reads.

- [ ] Execute B1 steps (format helpers; manifest/sections cannot disagree; `collected`-empty vs
      `unavailable` vs `error` distinguishable; `self_hash` recompute + single-mutated-byte tests,
      docstring says corruption **not** tampering).
- [ ] Execute B2 (floor + stdlib-only tests; per-directory ruff config stopping `UP`).
- [ ] Execute B2b (entry shim; unsupported interpreter → valid all-`unavailable:unsupported_runtime`
      snapshot; non-Linux → no snapshot, non-zero exit).
- [ ] Execute B3 (`agent/redact.py` superset test against `core/redaction.py` token families).
- [ ] Commit per B1–B3 boundaries.

---

## Task 3: Collector allowlists, runner, receipt (parent Phase C)

**Authority:** execute parent plan tasks **C1, C2, C3, C4** as written.

**Files:** Create `agent/allowlist.py`, `agent/run.py`, `agent/readfile.py`, and the receipt
assembly; Test under `tests/agent/`.

**Produces:** the argv-only runner (`run.command(entry) -> CommandResult` with exit/timeout/cap/
refusal recorded), the allowlisted file reader, and the receipt that Task 4's modules append to.

- [ ] Execute C1 (commands/files as data, reason + `reason_id` per entry; tests: every entry has a
      reason, no verb outside the read-only set, no entry interpolates anything). **Review Focus 4.**
- [ ] Execute C2 (argv-only; fixed binary dirs; scrubbed env; timeout; output cap with truncation
      recorded; exit captured. Tests against fake binaries: non-zero exit, timeout, missing binary,
      oversized output, refusal). **Review Focus 2 and 4.**
- [ ] Execute C3 (allowlisted paths; key extraction only; symlink/FIFO/ownership refusals and
      truncation recorded).
- [ ] Execute C4 (receipt assembled as C2/C3 run; test: every command and file appears once with its
      `reason_id`; every refusal appears).
- [ ] Commit per C1–C4 boundaries.

---

## Task 4: Collection modules — the demo subset (parent Phase D, scoped)

**Authority:** parent plan tasks **D1, D2, D4, D5**. **D3 (listening sockets, services) is out of
this slice** — neither finding needs it.

**Files:** Create `agent/modules/os_release.py`, `agent/modules/kernel.py`,
`agent/modules/host_identity.py`, `agent/modules/packages.py`, `agent/modules/ssh.py`; Test under
`tests/agent/modules/`.

**Produces:** snapshot `sections`:
- `os_release` — `ID`, `VERSION_ID`, pretty name (D1).
- `kernel` — the **running** kernel string (D1), collected via the allowlisted read (e.g. `uname -r`
  / `/proc/version`), and a field stating whether the running kernel is the box's own or shared (the
  value Task 6's `not_applicable` branch reads for a container).
- `host` identity — hostname, `machine_id_fingerprint` (D1).
- `packages` — dpkg names + versions only; the kernel-package entries are what the reboot check
  reads (D2). **No security-data matching touches this in the demo.**
- `ssh` — effective `sshd` config keys, enough for `PermitRootLogin` (D4).

- [ ] Write each module's facts-and-status test first (D1/D2/D4), using recorded fake-host-tree
      inputs; run; expect FAIL.
- [ ] Implement each module (facts + `status`, judging nothing).
- [ ] Execute D5: the grep test that fails on judgement words (`insecure`, `weak`, `vulnerable`) in
      any module.
- [ ] Run; expect PASS. Commit per module.

---

## Task 5: Minimisation proof + explainability (parent Phase E)

**Authority:** execute parent plan tasks **E1, E2, E3, E4** as written — kept even for a demo; they
are what gets an agent accepted onto a fleet.

**Files:** Test `tests/agent/test_minimisation.py`, `tests/agent/test_determinism.py`; the
`--explain` / `--explain-plan` paths in `agent/__main__.py`.

- [ ] Execute E1 (fake host tree with canaries of every family; **no canary value appears in the
      snapshot bytes, error paths included**). **Review Focus 3.**
- [ ] Execute E2 (two runs, timestamps/durations/monotonic masked, diff empty).
- [ ] Execute E3 (`--explain`: receipt as plain text naming every command and refusal).
- [ ] Execute E4 (`--explain-plan`: full allowlists + every exclusion printed, **nothing executed** —
      `subprocess`/`open` seams that fail the test if touched).
- [ ] Commit.

---

## Task 6: The `host` scanner — reader, hostile-input guard, the two checks (parent Phase F, scoped)

**Authority:** parent plan **F1, F1b, F1c, F2, F3**. **F4 (distro security matcher) is excluded** —
gated on A2's licence sign-off, not in this slice.

**Files:** Create `scanners/host/scanner.py`, `scanners/host/reader.py`, `scanners/host/checks.py`;
Modify `cli/` to add `scan run host --snapshot <file>` and register `host` via `core/registry.py`;
Test under `tests/scanners/host/`.

**Consumes:** the snapshot shape from Task 2 (B1/B2b) and Task 4's sections.
**Produces:** two findings with `check_id` `host-ssh-root-login` and `host-kernel-reboot-pending`.

### 6a — reader + hostile input (F1/F1b/F1c)

- [ ] **Step 1:** Write failing tests, one per failure: unknown `snapshot_version` → scan error;
      manifest/sections disagreement → scan error; malformed → scan error; `self_hash` mismatch →
      scan error naming the mismatch; an all-`unsupported_runtime` snapshot → a host reported
      **unassessed and named**, never clear (F1).
- [ ] **Step 2:** Write failing hostile-input tests **before any field is read** (F1b): pre-parse
      limits (total size, nesting depth, per-field string length, per-array length, key count) each a
      named constant with its reason, exceeding any one a **scan error never a truncation**; no
      snapshot value becomes a path/arg/URL/identifier/format string (`../../etc/passwd`, `/dev/stdin`,
      a NUL byte, a 4 KB name, `.`, empty string); wrong type → scan error **naming the field**.
      **Review Focus 5.**
- [ ] **Step 3:** Write failing render-boundary tests (F1c): `<script>alert(1)</script>`, an ANSI
      sequence, a very long single-line value — asserted **present and inert** in JSON, HTML, PDF and
      terminal output (positive assertion: a dropped value is an R1 failure).
- [ ] **Step 4:** Run; expect FAIL. Implement `reader.py`. Run; expect PASS. Commit.

### 6b — the two checks (F2/F3)

- [ ] **Step 5:** Write the failing check tests against recorded fixtures (filled in Task 8):
```python
def test_ssh_root_login_fires_on_permit_yes(positive_snapshot):
    f = run_host_check("host-ssh-root-login", positive_snapshot)
    assert f.severity == "high"
    assert f.evidence.control == "prohibit-password"   # allowlist's declared expectation
    assert f.evidence.test == "yes"                     # what the snapshot holds
    assert f.evidence.receipt_ref is not None
    assert f.state != "confirmed"                        # one method (spec §9)

def test_ssh_root_login_silent_on_clean(clean_snapshot):
    assert run_host_check("host-ssh-root-login", clean_snapshot) is None

def test_reboot_pending_fires_when_installed_newer(positive_snapshot):
    f = run_host_check("host-kernel-reboot-pending", positive_snapshot)
    assert f.state == "highly_likely"                    # package finding ceiling (spec §9)
    assert f.evidence.control == running_kernel(positive_snapshot)
    assert f.evidence.test == newest_installed_kernel(positive_snapshot)

def test_reboot_pending_silent_on_clean(clean_snapshot):
    assert run_host_check("host-kernel-reboot-pending", clean_snapshot) is None

def test_reboot_not_applicable_on_container(container_snapshot):
    f = run_host_check("host-kernel-reboot-pending", container_snapshot)
    assert f.state == "inconclusive" and "not_applicable" in f.reason   # shared kernel, never a pass

def test_errored_section_is_inconclusive_not_pass(ssh_errored_snapshot):
    f = run_host_check("host-ssh-root-login", ssh_errored_snapshot)
    assert f.state == "inconclusive" and "error" in f.reason            # R1/R2
```
- [ ] **Step 6:** Run; expect FAIL. Implement `checks.py`: checks over `collected` sections only; an
      `error`/`unavailable` section → `inconclusive` naming the reason (F2). Each finding cites its
      section + receipt line; `detection_methods[]` with honest single-method independence classes
      (F3). Kernel-version comparison resolves Ubuntu package ordering vs `uname -r` (builder's call,
      pinned by the fixtures).
- [ ] **Step 7:** Run; expect PASS. Commit.

### 6c — ingest + registration

- [ ] **Step 8:** Write a failing CLI test: `scan run host --snapshot <fixture>` emits the findings;
      `host` appears in `scan list` with the version/mode/target-type from Global Constraints.
- [ ] **Step 9:** Run; expect FAIL. Add the `--snapshot` flag and register `host` via
      `core/registry.py`. Run; expect PASS. Commit.

---

## Task 7: Stand up the lab boxes and record snapshots (Step 3, demo-scoped)

**Operator + me.** No platform code; produces the fixtures Task 8 commits. Per ADR-027 snapshots are
**recorded**, never hand-written.

- [ ] **Operator:** a VMware Ubuntu 22.04 VM, purpose-built, not on this server, discardable.
- [ ] **Record the clean-state snapshot first** (decision (b), spec §8): run the collector on the VM
      **before** root login is enabled and **before** the extra kernel is installed → the reboot/SSH
      negative. Record the "flip one box" caveat with the fixture.
- [ ] **Operator:** apply the two misconfigurations — `PermitRootLogin yes`; install a newer kernel
      package, **do not reboot**.
- [ ] **Record the positive snapshot** on the misconfigured VM.
- [ ] **Record the SSH-clean container snapshot** (clean Ubuntu 22.04 container) and, for the
      `not_applicable` case, note its shared-kernel `kernel` section.
- [ ] Record, if needed for the R1 case, a snapshot whose `ssh` section is present with status
      `error` (D67 — contains the thing the case tests, never omits it).

**Exit:** four recorded snapshots in hand (positive, clean-state VM negative, clean container,
ssh-errored), copied to the platform.

---

## Task 8: Corpus and gate (parent Phase G)

**Authority:** parent plan **G1, G2, G3**.

**Files:** Create `corpus/fixtures/host/<case>/` per case; Modify `SPEC.md` (the `host` row); the
corpus harness entry for a file-ingest scanner.

- [ ] **Step 1:** Commit Task 7's recorded snapshots as fixtures (G1), one case per snapshot, each
      case's expected findings written down.
- [ ] **Step 2:** Add the D67 harness assertion: every case's expected outcome is traceable to
      something present in its artefact (the `not_applicable`/`error` cases must **contain** the
      section with that status, never omit it) (G2).
- [ ] **Step 3:** Run `make corpus`; record the gate's three numbers **with the claim count** in
      `SPEC.md`, and flip `host` from PLANNED to its real status (G3).
- [ ] **Step 4:** Commit.

**Exit:** `scan run host --snapshot corpus/fixtures/host/positive/snapshot.json` reproduces both
findings; the clean case produces neither; `make corpus` passes with `host`'s numbers published.

---

## Self-review notes

- **Spec coverage:** every §6 slice element maps to a task — prereqs §6.1 → Tasks 1 & 7; lab box §6.2
  → Task 7; collector §6.3 → Tasks 2–5; scanner §6.4 → Task 6; ceilings §6.5 → Task 6 Step 5
  assertions; corpus §6.6 → Task 8.
- **Excluded by design, confirmed absent from tasks:** packages security matcher / F4, D3
  sockets/services, network path, distribution-agnostic collection, signing, correlation/fleet view.
- **Proportion:** shared machinery (Tasks 2, 3, 5) is referenced to the parent plan, not
  re-transcribed; full TDD detail is written only for the genuinely new code (Task 1's test shape,
  Task 6's two checks and ingest, Task 8's fixtures).
