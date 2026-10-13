# Host agent (docs/26 Step 2 → Steps 4–5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax. **Nothing in this plan is started: it is approved first by the operator** (his standing
> rule for D59, D60 and the lab entry point).

**Goal:** a one-shot, read-only host collector (`agent/`) that writes one versioned snapshot per
host with a command receipt inside it, and a platform-side `host` scanner that turns a snapshot into
findings on the existing frozen contract — with the artefact discipline of D39/D63/D67 built in,
so nothing the platform claims is absent from the artefact and no collection error can read as
"clean".

**Spec:** `docs/superpowers/specs/2026-10-13-host-agent-design.md`. Read it before any task; §2 (the
artefact rule) governs every other section.

**Architecture:** collector gathers facts and judges nothing; scanner judges and collects nothing.
The snapshot is to the `host` scanner what a fixture directory is to `--replay`.

## Global constraints

- **`core/` and `contracts/` are import-only for the scanner, and off-limits to the collector
  entirely.** `agent/` imports the standard library and `agent/` only — not `core/`, not
  `contracts/`, not `scanners/`. Enforced by a test.
- **Python 3.6 syntax floor inside `agent/`**, enforced by `ast.parse(..., feature_version=(3, 6))`
  over every `agent/` file; mypy runs `agent/` at `python_version = 3.8` (mypy's own floor). The
  floor lives in **one** constant.
- **No new runtime dependency** anywhere, and no build step for the collector: it is plain `.py`
  files run by the host's `python3`.
- `shell=False` always; argv lists only; binaries resolved from a fixed directory list, never
  `PATH`; a scrubbed, fixed environment.
- **ADR-004 is absolute**: the collector reads. No write, no install, no service control, no network
  call of any kind. A verb outside the reviewed read-only set is inexpressible in the allowlist, and
  a test asserts that.
- Hard constraint 5: no secret value in the snapshot or the receipt, redacted at capture.
- Every count in the snapshot says what it counted (D64); there is no conflated total and
  deliberately no field named `requests` (D65).
- Scanner `name = "host"`, `version = "0.1.0"`, `target_types = {"host"}`, `vantage: agent`,
  `engagement: defensive` (ADR-034). `state` never hand-set.
- Line length 100, ruff `E,F,I,UP,B,SIM,N,RUF`, mypy strict. **`UP` must not be allowed to rewrite
  `agent/` to 3.9+ syntax** — per-directory ruff config, with the reason in the config.
- Commit trailer per the active session; `.claude/` is never staged.

## Review focus (what a reviewer should attack)

1. **A section that silently disappears.** Delete a section after collection and assert the scanner
   raises a scan error rather than reporting clear (R1).
2. **A command that fails mid-run.** Non-zero exit, timeout, binary absent, output over cap — each
   must land as `status: error` with the reason, in both the section and the receipt (R2).
3. **A secret on an error path.** A parse failure must not quote the failing line; a refused path
   must not echo content. The canary test asserts on raw bytes, errors included.
4. **The allowlist as a shell.** No argument may come from collected data; no entry may resolve a
   binary through `PATH`; no path may traverse a symlink out of its directory.
5. **Two runs, one host.** Determinism with timestamps masked; a diff is a real change, which is
   what makes the receipt reviewable by the server's owner.
6. **The 3.6 floor.** Syntax check passes, and the collector is *not* claimed to run on 3.6 until it
   has run on a 3.6 lab box (Step 3).

---

## Phase A — Step 2 deliverables: the decisions, written down (no collector code)

- [ ] **A1. ADR-035** in `docs/02-decisions.md` (the number is reserved): the thin one-shot collector;
      judgements platform-side; the language decision with the fleet assumption **stated as an
      assumption** and §3.1's costs recorded; the versioned snapshot; the two allowlists; data
      minimisation; the vulnerability-data decision with its licence evidence; the receipt designed
      in; **the artefact rule (R1/R2) as a numbered decision**, since it is the one that changes the
      shape of everything else. Record `agent/` as a new top-level directory, which CLAUDE.md
      requires a deliberate decision for.
- [ ] **A2. `tools/registry.yaml`:** entries for the Ubuntu security data (CC BY-SA 4.0, URL + the
      README's licence sentence), Red Hat Security Data (CC BY 4.0 + its attribution requirement),
      and Debian Security Tracker (**licence not stated** — recorded as the finding, not a guess).
      All three **PENDING**, awaiting the operator, in the IANA pattern. Note Red Hat's OVAL v2
      deprecation.
- [ ] **A3. Ledger:** the Debian licence question; the attribution obligation Red Hat's CC BY 4.0
      puts on report text; the Python-3.6-floor cost and the fact that nothing has run on 3.6 here;
      the deliberate duplication of redaction patterns in `agent/` with its reason.
- [ ] **A4. docs/26:** tick Step 2's items; `SPEC.md` gains the `host` scanner as **PLANNED** with no
      numbers (no figure is published before a gate exists).

**Exit:** ADR-035, this plan and the spec approved by the operator. **Nothing below starts first.**

## Phase B — The snapshot contract, tests first

- [ ] **B1.** `agent/snapshot.py`: the format of §4 as construction helpers — `manifest`, per-section
      `status`, the named `counts`. Tests first, including: manifest and sections cannot disagree;
      "collected and empty" is distinguishable from `unavailable` and from `error`; an unknown status
      is impossible to construct.
- [ ] **B2.** The 3.6 floor test and the stdlib-only import test (both over `agent/`), plus the ruff
      per-directory config that stops `UP` modernising the directory.
- [ ] **B3.** `agent/redact.py` with its own pattern set, and the test that it is a superset of
      `core/redaction.py`'s token families, comparing the definitions directly.

## Phase C — The allowlists and the runner

- [ ] **C1.** `agent/allowlist.py`: commands and files as data, each with its reason, timeout, caps,
      `needs_root`, and `reason_id`. Tests: every entry has a reason; no verb outside the read-only
      set; no entry interpolates anything.
- [ ] **C2.** `agent/run.py`: argv-only execution, fixed binary directories, scrubbed env, timeout,
      output cap with truncation recorded, exit status captured. Tests first against fake binaries:
      non-zero exit, timeout, missing binary, oversized output, and a refusal.
- [ ] **C3.** `agent/readfile.py`: allowlisted paths, key extraction only, symlink/FIFO/ownership
      refusals recorded, truncation recorded.
- [ ] **C4.** The receipt (§8), assembled as these two run — not bolted on afterwards. Test: every
      command and file that ran appears exactly once, with its `reason_id`; every refusal appears.

## Phase D — Collection modules (facts only)

- [ ] **D1.** `os_release`, `kernel`, `host identity` (hostname, machine-id **fingerprint**).
- [ ] **D2.** `packages` (dpkg and rpm paths), as names and versions only.
- [ ] **D3.** `listening` sockets; `services` (unit files, enabled/disabled).
- [ ] **D4.** `ssh` config keys; `accounts` facts that do not need `/etc/shadow`.
- [ ] **D5.** Each module returns facts and a status, and **judges nothing** — a test greps the
      modules for judgement words (`insecure`, `weak`, `vulnerable`) and fails on them.

## Phase E — Minimisation proof

- [ ] **E1.** The fake host tree with canaries of every family we know (§6.5), and the test that no
      canary value appears in the snapshot **bytes**, error paths included.
- [ ] **E2.** The determinism test (two runs, timestamps masked).
- [ ] **E3.** `--explain`: the receipt as plain text for the server's owner. A test that it names
      every command and every refusal.

## Phase F — The `host` scanner (platform side)

- [ ] **F1.** Snapshot reader: unknown `snapshot_version` → scan error; manifest/sections
      disagreement → scan error; malformed → scan error. Tests first, one per failure.
- [ ] **F2.** Checks over `collected` sections only; a section that is `error` or `unavailable`
      produces an `inconclusive` **naming the reason**, never a pass. Tests first.
- [ ] **F3.** Evidence: each finding cites its section and the receipt line behind it;
      `detection_methods[]` with independence classes from the first finding (docs/23 item 8's
      shape, not retrofitted).
- [ ] **F4.** The distro security-data matcher: fixed-version-per-release only, **no CVE-range
      matching**; a package the feed does not cover is `inconclusive` with that reason. Vendored
      feed with `source` + `reviewed_on` and a freshness bound. **Gated on A2's sign-off.**

## Phase G — Corpus and gate (needs Step 3's lab boxes)

- [ ] **G1.** Snapshots **recorded** from lab boxes, never hand-written (ADR-027).
- [ ] **G2.** A negative case per positive, and — per D67 — a case asserting "could not read X" whose
      snapshot **contains** X with status `error`, not a snapshot missing X. A harness assertion that
      every case's expected outcome is traceable to something present in its artefact.
- [ ] **G3.** The gate's three numbers with its claim count, recorded in `SPEC.md` only once it
      exists. Until then `host` stays PLANNED with no figure.

## Open questions carried into the plan, not resolved by it

- **The fleet's OS/Python mix** (operator, before Step 4). If the floor is 3.8+, B2's constant and
  §3.1's annotation cost go away.
- **Debian's data licence** (A2) — ask, or restrict Alpha to Ubuntu and RHEL-family and say so.
- **Signing** (docs/23 item 7): out of Alpha; the format leaves room, and nothing claims to be
  verifiable until it is.
- **Nothing here has run on Python 3.6.** It cannot, on this machine. The claim stays "written and
  syntax-checked to the floor" until a 3.6 lab box runs it.
