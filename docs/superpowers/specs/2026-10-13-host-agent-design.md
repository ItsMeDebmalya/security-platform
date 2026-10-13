# Host agent — the one-shot collector and the `host` scanner — Design

*Design spec. Working artifact for the implementation plan, not part of the canonical doc set
(`SPEC.md` / ADRs / roadmap remain authoritative — this feeds changes into them, it does not
replace them). Date: 2026-10-13. [docs/26](../../26-alpha-build-sequence.md) **Step 2**, which the
operator held until the lab entry point merged (PR #50, 2026-10-12).*

Collector: **`agent/`** (new top-level, the first since `api/` and `web/`; recorded in ADR-035
because CLAUDE.md names the permitted new directories).
Scanner: **`host`**, in `scanners/host/`.

---

## 1. What is already settled, and what this spec decides

Settled in [docs/26](../../26-alpha-build-sequence.md) and ADR-033, and not reopened here: the
collector collects **facts only**, makes no judgements, is **not a daemon**, has **no listener** and
**no auto-update**, writes **one snapshot file per host**, and **runs once and exits**. Judgements
happen platform-side, in a `host` scanner on the existing frozen contract. The agent adds **no new
external scanner**; new value goes into its modules.

This spec decides the seven things Step 2 lists, and one the operator added when commissioning it:

| # | Decision | §
|---|---|---|
| 1 | Language and the runtime floor, with the fleet assumption stated | §3 |
| 2 | The versioned snapshot format | §4 |
| 3 | The command allowlist and the file allowlist, a reason per entry | §5 |
| 4 | Data-minimisation rules, and the test that no snapshot holds a secret value | §6 |
| 5 | The vulnerability data source, with licence evidence gathered | §7 |
| 6 | The command receipt, designed in rather than retrofitted (docs/23 item 10) | §8 |
| 7 | The platform side: the `host` scanner and how a snapshot becomes findings | §9 |
| 8 | **The artefact rule** the operator carried over from the replay work (D39/D63/D67) | §2 |
| 9 | **The unsupported-runtime case** — a host with no usable Python still produces a snapshot | §3.3 |
| 10 | `agent/` as a new top-level directory: the alternatives considered, not just the outcome | §11 |
| 11 | Where Red Hat's CC BY 4.0 attribution has to appear, as a Step 8 design input | §7.4 |

---

## 2. The artefact rule — the operator's carry-over, and the spine of this design

> *"The snapshot is a recorded artefact that the platform replays into findings, which is the same
> shape as the corpus fixtures. Every lesson from D39, D63 and D67 applies to it."* — operator,
> 2026-10-13

Three times now a corpus case has passed because the artefact did not contain what the case claimed
to test: **D28** (expiry proven against fixtures that could not express it), **D31** (takeover
fingerprints), **D67** (a case asserting "the upstream failed" that recorded *no fixture at all*, so
a `MissingFixtureError` stood in for the failure). All three came from a generator simulating a
third party rather than recording one. The web Light plan predicted this exact hazard in writing on
2026-10-06 and it still took D66 to surface it.

A snapshot is the same kind of artefact, produced by a program on someone else's machine, read later
by a scanner that will make claims from it. So two rules are structural here, not advisory:

- **R1 — Everything claimed is present.** The platform may claim only what the snapshot contains. A
  section the collector was supposed to produce is always present with an explicit status; it is
  never simply missing. The snapshot declares, in its own manifest, every section that *should* be
  there, so the scanner can tell "collected and empty" from "never collected".
- **R2 — An error is recorded as an error.** A command that failed, a file that could not be read, a
  path the allowlist refused, a timeout, a truncation: each is recorded **as that**, in the section
  it belongs to and in the receipt. An error must never become an absence that later reads as
  "clean". This is D64's lesson in its general form, and the reason `status` is mandatory per section
  rather than inferred.

The platform side enforces both: a `host` finding may cite only a section whose status is
`collected`, and a section with status `error` or `unavailable` produces an `inconclusive` that says
so — never a pass. **A missing section is a scan error** (`ScanError`), not an inconclusive and
certainly not a clear. The same discipline as `ResolverNotWiredError` after D66.

---

## 3. Language and runtime floor

**Decision: Linux only.** Confirmed by the operator, 2026-10-13: **no Windows, no macOS, no BSD in
Alpha.** Stated here rather than implied by the allowlist's paths. A non-Linux host is out of scope
for the collector entirely; it is not a host that reports `unavailable`, it is a host the collector
is never put on. (The one place this surfaces technically: `sys.platform` is checked as the
collector's second act, after §3.3's interpreter check, and a non-Linux platform exits non-zero with
that message and writes no snapshot — there is no partial snapshot to misread.)

**Decision: Python 3, standard library only, no third-party package, no build step, no compiled
artefact.** One language for the collector and the platform; auditable by reading one directory; no
supply chain on the host beyond the host's own Python.

**Fleet assumption, as instructed, to be confirmed or corrected by the operator before Step 4:**

| Distribution | Default `python3` | Status |
|---|---|---|
| Ubuntu 18.04 LTS | 3.6.9 | the floor |
| Ubuntu 20.04 / 22.04 / 24.04 | 3.8 / 3.10 / 3.12 | comfortable |
| Debian 10 | 3.7.3 | comfortable |
| Debian 11 / 12 | 3.9 / 3.11 | comfortable |
| RHEL-family 8 | 3.6.8 (`/usr/libexec/platform-python`) | the floor |
| RHEL-family 9 | 3.9 | comfortable |

So the floor is **Python 3.6**, set by Ubuntu 18.04 and RHEL 8.

### 3.1 What the 3.6 floor costs, said now rather than worked around later

The operator asked to be told now if standard-library Python over that range forces something ugly.
It forces four things. None is fatal; one is a real gap.

1. **Annotation style.** No `from __future__ import annotations` (3.7+) and no PEP 585 builtin
   generics (`list[str]`, 3.9+). Inside `agent/`, annotations must be `typing.List[str]`,
   `typing.Optional[int]`, and every annotation must be valid *at runtime* on 3.6. The rest of the
   repo is 3.13-native. **This is the ugly part**: one directory with a deliberately older dialect.
   Contained, and enforced rather than hoped for — see 3.2.
2. **No `dataclasses`** (3.7+). Not a loss: a snapshot is JSON, so the collector builds plain dicts
   and lists, which it would have to do anyway.
3. **No `subprocess.run(capture_output=…)`** (3.7+), no walrus (3.8+), no f-string `=` (3.8+).
   Mechanical: `stdout=PIPE, stderr=PIPE`.
4. **We cannot execute 3.6 here.** This box has 3.13 only (`.python-version`), and the repo's venv is
   3.13. **So the collector's behaviour on 3.6 is unproven until it runs on a 3.6 host**, which the
   Step 3 lab boxes provide. Recorded as a condition, not glossed: until then the claim is "written
   to the 3.6 floor and syntax-checked against it", never "runs on RHEL 8".

**If the operator's fleet turns out to be 3.8+ everywhere**, item 1 disappears, items 2–3 become
free, and the only change is one constant and the enforcement test's `feature_version`. That is why
the floor lives in exactly one place.

### 3.2 How the floor is enforced rather than remembered

`ast.parse(source, feature_version=(3, 6))` (available 3.8+, so it runs under our 3.13) rejects
syntax newer than the floor. A test parses every file under `agent/` that way, and a second test
asserts no `agent/` module imports anything outside the standard library or `agent/` itself —
including, deliberately, nothing from `core/`, `contracts/` or `scanners/`. The collector ships to
hosts; it must not drag the platform with it. mypy's own floor is 3.8, so `agent/` is type-checked at
`python_version = 3.8` and the 3.6 syntax floor is the AST test's job. **Neither test proves it runs
on 3.6** (3.1, item 4); they stop it drifting past the floor between now and the lab boxes.

### 3.3 The unsupported runtime — an R2 hole, closed

The operator found this: §3 above assumed a usable `python3` exists. On a host with only python2, a
`python3` below the floor, or no Python at all — RHEL 7 and Ubuntu 16.04 are real possibilities in a
fleet nobody has inventoried yet — the collector as described produces **nothing**. Nothing is an
absence, and R2 forbids absences. Worse, the hosts that cannot run it are by construction **the
oldest and least-patched machines in the fleet**, so a fleet report that quietly omits them omits
exactly the hosts the report exists to find. That is the worst available failure mode for this
product.

**Decision: the collector's first act is to detect its own interpreter, and an unsupported runtime
produces a valid snapshot rather than no snapshot.**

- A tiny **entry shim** (`agent/__main__.py`, and the `agent.py` single-file bundle) is written to a
  dialect every Python 3 and Python 2.7 can at least *parse*: no annotations, no f-strings, no
  keyword-only arguments — nothing past 2.7 syntax — so it does not die with a `SyntaxError` before
  it can report the problem. It checks `sys.version_info` against the floor constant and nothing
  else, then imports the real collector only if the check passes.
- On an unsupported runtime it writes a **valid snapshot** at the requested path: the real
  `snapshot_version`, the real `schema`, `collected_at`, the host identity it can obtain without
  running anything (hostname, and `/etc/os-release` read as text if readable), and a `manifest` in
  which **every declared section is present with `status: "unavailable"` and
  `reason: "unsupported_runtime"`**. `sections` is empty, `counts` reflects zero commands, and the
  `receipt` records the interpreter that was found.
- The snapshot records what was found, so the finding is actionable rather than merely negative:
  `runtime: {"found": "2.7.5", "executable": "/usr/bin/python", "required": "3.6", "searched":
  ["/usr/bin/python3", "/usr/libexec/platform-python", …]}`.
- **No Python at all** is the one case the collector cannot report on its own, because it cannot run.
  It is covered by the fleet probe (plan task A5), which is POSIX `sh` precisely so that the hosts
  without a usable Python are the ones it still works on. A host that appears in the probe and
  produces no snapshot is a known gap, not a silent one.
- **The platform side:** a snapshot whose sections are all `unavailable: unsupported_runtime` is a
  first-class result — the `host` scanner reports **a host it could not assess**, with the
  interpreter version it found and the floor it needed. Not an error, not a clear, not an empty
  pass. A test asserts the fleet view counts that host as unassessed and names it.

---

## 4. The snapshot format

One file per host, JSON, UTF-8, newline-terminated, written to a path the operator names.

```
{
  "snapshot_version": 1,
  "schema": "security-platform/host-snapshot",
  "collector_version": "0.1.0",
  "collected_at": "2026-10-13T09:14:22Z",          // UTC, from the host clock
  "clock": {"source": "host", "tz_offset_minutes": 330, "monotonic_ms": 184221},
  "host": {"hostname": "...", "machine_id_fingerprint": "sha256:…(16)", "os": {...}},
  "manifest": [                                     // R1: what SHOULD be here
    {"section": "os_release",  "status": "collected"},
    {"section": "packages",    "status": "collected"},
    {"section": "listening",   "status": "error", "error": "command_failed:ss:127"},
    {"section": "accounts",    "status": "unavailable", "reason": "needs_root"}
  ],
  "sections": { "os_release": {...}, "packages": {...}, ... },
  "receipt": { ... },                               // §8, inside the artefact, not beside it
  "self_hash": "sha256:…",                          // over the snapshot with this field excluded
  "counts": {                                       // D64/D65: each count says what it counted
    "commands_run": 11, "commands_refused": 0, "commands_failed": 1,
    "files_read": 7, "files_refused": 0, "bytes_read": 48213,
    "sections_collected": 6, "sections_unavailable": 1, "sections_error": 1
  }
}
```

Rules that are part of the format, not of the implementation:

- **`snapshot_version` is an integer and changes when a reader could misread an older file.** The
  scanner refuses a version it does not know, loudly: an unknown snapshot is a scan error, never a
  best-effort parse. Additive section changes do not bump it; a changed meaning does.
- **Every section in `manifest` exists in `sections` or has a non-`collected` status.** A test
  asserts the two cannot disagree (R1).
- **`status` is one of `collected` | `unavailable` | `error`,** and `unavailable` carries a machine
  reason (`needs_root`, `not_installed`, `not_applicable_os`) while `error` carries what failed.
  "Nothing found" is `collected` with an empty body — distinguishable from both (R2).
- **No count is a single conflated total.** `counts` names what each number counted, which is D64's
  rule and avoids repeating D65 in a new artefact. There is deliberately no `"requests"`.
- **No wall-clock arithmetic on the platform.** The host's clock may be wrong, so the snapshot
  records the offset and a monotonic reading, and anything time-sensitive is judged against
  `collected_at` with the skew stated — the same discipline as `days_until_expiry(now=…)` for a
  replayed handshake.
- **Determinism.** Two runs on an unchanged host differ only in timestamps, durations and the
  monotonic reading. A test runs the collector twice against a fake host tree and diffs with those
  fields masked. This is what makes a snapshot reviewable by the person who owns the server.
- **Size cap**, with truncation recorded per item (never silent), and a total cap that, if hit,
  becomes an `error` section rather than a half-written file.
- **A self-hash, and what it is honestly for.** `self_hash` is SHA-256 over the serialised snapshot
  with the `self_hash` field itself excluded (the field set to `null`, then the canonical
  serialisation hashed — the procedure is written down so a reader can recompute it). It catches
  **truncation and accidental corruption in transit**, which is a real risk when a file is copied by
  hand off fifty machines.
  **It is not tamper-evidence and this spec must not be read as claiming it is:** a writer who
  changes the content can recompute the hash. It detects accident, not intent. Signing — the thing
  that would detect intent — stays deferred to docs/23 item 7, and the format leaves room for a
  detached signature. A mismatch on the platform side is a **scan error** naming the mismatch, since
  a corrupt artefact is precisely what R1 says may not be claimed from.

---

## 5. The allowlists

The pattern is the one D56/PR #44 established for testssl.sh and `core/authz.py`: **an exact
allowlist, a reason per entry, enforced at runtime, with no way to pass anything else.**

### 5.1 Commands

- `argv` lists only. **`shell=False` always**; no string command ever reaches `subprocess`.
- The binary is resolved against a fixed directory list (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`,
  and RHEL's `/usr/libexec` for `platform-python`), never `PATH`, and the resolved path must be a
  regular file, not a symlink out of those directories.
- The environment is **scrubbed**, not inherited: a fixed minimal env (`LC_ALL=C`, `PATH` from the
  same fixed list, `TZ=UTC`), so output is parseable and nothing the host's profile sets can change
  what we read. This is `core/testssl.py`'s `environment()` rule applied to every command.
- Each entry carries: the argv template, **why it is needed**, what it is read for, its timeout, an
  output cap, and whether a non-zero exit is expected on some systems.
- No command may take a value derived from collected data. Arguments are constants. (Nothing
  interpolates a package name into a second command: that is how an allowlist becomes a shell.)
- **Read-only by construction**: every entry is a query verb (`dpkg-query -W`, `rpm -qa`, `ss -ltnp`,
  `systemctl list-unit-files --type=service`, `sshd -T` where readable, `uname -a`). Anything that
  writes, starts, stops, installs or dials out is inexpressible, not merely discouraged. A test
  asserts the allowlist contains no verb outside a reviewed set.

### 5.2 Files

- Exact paths, or exact directory + a fixed filename pattern (`/etc/ssh/sshd_config.d/*.conf`).
- **Never whole files into the snapshot.** Each entry declares the keys it may extract (e.g. from
  `sshd_config`: `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, …), and only those
  key/value pairs are kept. A file is read; a file is not stored.
- A reason per entry, and what the platform will judge from it.
- Paths are opened with `O_NOFOLLOW` semantics on the final component and must be regular files
  owned by root or the collector's user — a symlink or a FIFO is a refusal recorded in the receipt,
  not an error that aborts the run.
- **Explicitly excluded, in the allowlist file itself so the exclusion is reviewable:** private keys
  (`/etc/ssh/ssh_host_*_key`, `*.pem`, `*.key`), `/etc/shadow`, anything under `~/.ssh`, `.env`
  files, cloud credential files, token caches. Where their *presence or mode* is the fact we want,
  we record presence, mode and a fingerprint — never a byte of content (§6).

### 5.3 Privilege

The collector **runs as an unprivileged user by default** and does not ask for root. What needs root
is declared in the allowlist with `needs_root: true`; when it is not available, that section is
`unavailable` with reason `needs_root` (R1/R2), never absent. Running it under `sudo` is the
operator's choice, recorded in the receipt as the effective uid, so a reader can see which answers
were privileged.

---

## 6. Data minimisation, and the test that no snapshot holds a secret

Hard constraint 5 says never store customer secrets, **redacted at capture time, not at display
time**. For a collector that reads config files, that has to be structural:

1. **Allowlisted keys only** (§5.2). The default is not "collect and filter" but "collect nothing
   unless an entry names it".
2. **Secrets by type, never by value.** Where the fact is "a key exists" or "a password is set", the
   snapshot records presence, type, mode, size and a truncated SHA-256 fingerprint — the pattern
   already used for certificate and DKIM keys. A fingerprint is for change detection; it is never
   presented as proof of a value.
3. **Deny-list at the value level, after extraction**: any extracted value whose key or shape looks
   like a credential (`*password*`, `*secret*`, `*token*`, `*_key`, base64 blobs over a length
   threshold, PEM markers) is replaced by its type and fingerprint before it is ever written.
4. **One redaction pass over the whole snapshot before writing** — including the receipt — so a
   secret that reaches the structure by a route nobody anticipated still does not reach the disk.
   The collector cannot import `core/redaction.py` (§3.2: stdlib only), so it carries its own small
   pattern set, and a test asserts that set is a superset of the token families `core/redaction.py`
   recognises, comparing the two definitions directly. **Two copies of a rule drift** — that is
   ADR-036's own warning — so the test is the thing that keeps them honest, and the ADR records the
   duplication as a known cost with its reason (the collector must not ship `core/`).
5. **The test the operator asked for, stated as a property:** a fake host tree is planted with
   canary secrets of every family we know (an AWS example key, a PEM block, an API token, a
   password in `sshd_config`-shaped config, a `.env`), the collector runs against it, and **no
   canary value appears anywhere in the snapshot bytes** — sections, receipt, errors or truncation
   notes. Error paths included, because an error message is exactly where a value leaks: a parse
   failure must not quote the line it failed on. The canaries are ours (ADR: real positives come
   only from canaries), and the test asserts on the raw file, not on the parsed structure.

---

## 7. Vulnerability data source — decision with licence evidence

### 7.1 The judgement rule first

**Version strings lie** (CLAUDE.md; distros backport patches), and a version-only finding caps at
`suspected` with confidence ≤ 0.6. A host scanner that matched installed versions against CVE
ranges would be a false-positive generator and would break that rule by design. So:

> **Decision:** the `host` scanner judges packages against **the distribution's own security data**,
> which states the fixed version *for that release*, with the vendor's backports already accounted
> for. It does not do CVE-range matching, and it makes no claim about a package the distro's feed
> does not cover.

A package the feed does not cover is `inconclusive` with that reason, not silence — R2 again.

### 7.2 Candidates, with the licence evidence gathered today (2026-10-13)

| Source | What it gives | Licence as published | Evidence |
|---|---|---|---|
| **Ubuntu Security Notices / Ubuntu OSV records** (`canonical/ubuntu-security-notices`, `security-metadata.canonical.com/osv/`) | per-release fixed versions, USN↔CVE | **CC BY-SA 4.0** — the repository README states "This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License" | repo README + licence badge, read 2026-10-13 |
| **Red Hat Security Data** (CSAF/VEX, OVAL v2, Security Data API) | per-release fixed versions for RHEL-family | **CC BY 4.0** — "The data resources linked on this page as well as their alternative representations available through the Security Data API are licensed under the Creative Commons Attribution 4.0 International License", with "you must provide attribution to Red Hat … and provide a link to the original" | access.redhat.com/security/data, read 2026-10-13 |
| **Debian Security Tracker** (`security-tracker-team/security-tracker`, `security-tracker.debian.org`) | per-release fixed versions, DSA↔CVE | **not stated anywhere I could find.** No LICENSE visible on the Salsa project page; the Debian security team's own tracker page describes the data and its MITRE-derived CVE list but states no licence | Salsa project page and security-team.debian.org, read 2026-10-13 |
| **OSV.dev** as the aggregator | one format over all of the above | **per upstream source, not one platform licence** (GitHub/PyPI/Go advisories CC BY 4.0; Rust and GSD CC0) — so using OSV does not simplify the licence question, it only moves it | osv.dev upstream listings; the "OSVDB" licence that search engines surface is a different, defunct database and must not be applied here |

### 7.3 What that means for the register, and what is *not* assumed

- **Ubuntu's CC BY-SA 4.0 is the one that needs the operator's eye**, and it is why this is a
  sign-off and not a note. ShareAlike is fine for reading the feed; it has consequences if we
  publish a *derived database* of it. Our use is "read the vendor's statement about a package we
  found" — which is attribution-and-link territory — but ADR-003's discipline and the Wappalyzer
  precedent (hard constraint 4: a GPL *dataset* cannot seed ours) say a data licence gets the same
  scrutiny as a code licence. Registered **PENDING**, with the licence text and the URL, exactly as
  the IANA entry is PENDING until the operator reads the page himself.
- **Debian is registered PENDING with "licence not stated" as the finding**, not with a guess.
  Third-party aggregators claiming "public domain" for Debian advisories are not Debian and are not
  evidence. The open question for the operator: ask Debian, or restrict Alpha to Ubuntu and
  RHEL-family and say so.
- **Red Hat's CC BY 4.0 carries an attribution requirement we have to actually honour** wherever a
  finding rests on it — which is a report-text obligation, recorded now so it is designed in rather
  than discovered at report time. Also recorded: **Red Hat is retiring OVAL v2** in favour of
  CSAF/VEX, so building on OVAL v2 would be building on a deprecated feed; the design targets
  CSAF/VEX (or the distro's OSV records) and the ledger carries the deprecation.
- **No feed is bundled into the repo in Step 2.** The feed is fetched and vendored deliberately, with
  `source` + `reviewed_on` per entry and a freshness bound, like the EOL and fingerprint tables.

### 7.4 Where Red Hat's attribution has to appear — named, so Step 8 inherits it

CC BY 4.0 requires attribution to Red Hat **and a link to the original**. "We will attribute
somewhere" is not a design input; a place is. So, named now, as a requirement on the report spec
(docs/25) and on Step 8:

| Where | What appears | Why there |
|---|---|---|
| **Each finding that rests on the feed**, in its evidence block | the source name, the advisory/CVE id, and the **link to Red Hat's page for that advisory** | the attribution travels with the claim, so it survives a finding being exported, quoted or read alone |
| **The report's data-sources section**, once per report (JSON, HTML and PDF alike) | "Vulnerability data for RHEL-family hosts: Red Hat Security Data, © Red Hat, Inc., licensed CC BY 4.0", with the link to `access.redhat.com/security/data` and the licence link | the once-per-document notice, in the format a reader of a PDF can actually see |
| **The JSON report**, machine-readable | a `data_sources[]` entry with `name`, `licence`, `licence_url`, `source_url`, `retrieved_on` | a consumer of the JSON inherits the obligation rather than stripping it |
| **`tools/registry.yaml`** | the entry itself, with the licence text and the obligation spelled out | the register is where the obligation is discovered before use, not after |

The same shape covers Ubuntu (CC BY-SA 4.0, whose ShareAlike clause is about publishing a *derived
database*, not about this attribution), so the mechanism is one `data_sources[]` concept rather than
a per-vendor special case. **Rendering it is Step 8's work; owing it is recorded now.**

---

## 8. The command receipt, designed in (docs/23 item 10)

The backlog entry says this is cheap now and dear retrofitted; this is the "now". The receipt is
**part of the snapshot** (§4), not a sidecar file, so it cannot be separated from the thing it
describes or go missing in transit.

```
"receipt": {
  "receipt_version": 1,
  "collector_version": "0.1.0",
  "effective_uid": 1000, "effective_user": "svc-collector",
  "started_at": "...", "finished_at": "...", "duration_ms": 1841,
  "commands": [
    {"argv": ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
     "reason_id": "packages.debian",
     "exit_status": 0, "duration_ms": 221,
     "stdout_bytes": 41233, "stdout_truncated": false, "stderr_bytes": 0,
     "read_for": ["packages"]}
  ],
  "commands_refused": [
    {"argv_requested": [...], "refused_because": "not_in_allowlist"}
  ],
  "files": [
    {"path": "/etc/ssh/sshd_config", "reason_id": "ssh.config",
     "bytes_read": 3321, "keys_extracted": ["PermitRootLogin", "PasswordAuthentication"],
     "truncated": false, "mode": "0644", "owner_uid": 0}
  ],
  "files_refused": [
    {"path": "/etc/shadow", "refused_because": "excluded_by_allowlist"},
    {"path": "/etc/ssh/ssh_host_ed25519_key", "refused_because": "excluded_private_key"}
  ]
}
```

- **Every command run, with exact argv, exit status and what it was read for.** `reason_id` points
  at the allowlist entry, so a reader can see *why* it ran without reading our source.
- **What was read, named, never reproduced**: `keys_extracted` lists key names, not values.
- **Refusals are first-class.** A command or path the allowlist declined appears as a refusal — the
  part that actually demonstrates the controls ran, exactly as D60's recorded refusals do.
- **Every count says what it counted** (§4, D64). There is no single "operations" number.
- It goes through the same redaction pass as the rest of the snapshot (§6.4), because an argv or a
  path is as capable of carrying a secret as a body is.
- **It is for the server's owner, in their words**: the plan includes a `--explain` rendering of the
  receipt as plain text, so the person whose approval the rollout needs can read what the agent did
  without parsing JSON. That is the whole point of the backlog entry.

### 8.1 `--explain-plan` — what *will* run, before it runs

`--explain` is after the fact. The operator's point: the server owner whose approval the rollout
needs wants to see what will run **before** it runs, and that is the thing that gets the agent
accepted onto a fleet at all.

**`--explain-plan` prints the allowlists in full and executes nothing.** Every command with its
argv template, its `reason_id`, its reason in prose, its timeout and caps, and whether it needs
root; every file path with the keys it may extract and what the platform will judge from them; and
**every exclusion, listed explicitly** — `/etc/shadow`, private keys, `~/.ssh`, `.env`, credential
caches — because what the agent refuses to read is the part that earns the approval.

It is nearly free: the allowlists are already data (§5) with a reason per entry, and the renderer is
the same plain-text formatter `--explain` uses. Constraints: it runs no command, opens no
allowlisted file, needs no root, and a test asserts that invoking it executes nothing (a
`subprocess` seam that fails the test if touched) and that **every allowlist entry and every
exclusion appears in the output** — so the printed plan cannot drift from the enforced one.

---

## 9. The platform side: the `host` scanner

- `scanners/host/`, on the **existing frozen contract**, extended in Step 1 already: `host` target
  type, `vantage: agent`, `engagement: defensive` (ADR-034). **No contract change is needed and none
  is proposed.**
- Ingest: `scan run host --target <hostname> --snapshot <file>` reads a snapshot the operator has
  copied. **The collector never dials out and the platform never reaches into a host**; API upload
  comes after Step 7, as docs/26 says.
- **The snapshot is this scanner's recording.** Its relationship to the scanner is exactly
  `--replay`'s to a fixture directory, and it inherits the discipline: an unknown
  `snapshot_version`, a section the manifest promised but did not deliver, or a malformed snapshot is
  a **scan error**, never an inconclusive and never a clear (R1/R2, D66's rule).
- Findings cite the section they rest on and the receipt line that produced it, so every host
  finding's evidence chain ends at a command with its exact arguments. A control-vs-test pair is the
  allowlist entry's declared expectation versus what the snapshot holds.
- **`state`, and the independence ceiling — resolved in favour of §5.1.** An earlier draft of this
  section said `confirmed` comes from "a second, independent observation in the same snapshot (a
  package's version from the package database *and* the binary's own reported version)". The
  operator caught that this contradicts §5.1: running `<binary> --version` for a package just
  discovered in the package database **is an argument derived from collected data**, which is the
  exact thing §5.1 exists to forbid. §5.1 is the safety rule, so §5.1 wins and that sentence is
  withdrawn.
  **Decision: `confirmed` is not reachable for package findings in Alpha. They cap at
  `highly_likely`, and this spec says so plainly** rather than claiming an independence the
  allowlist cannot deliver. One package-database reading is one observation; `core/state.py` is left
  to do its job with the evidence that actually exists.
  The route to `confirmed` later is the other option the operator offered, and it is written down
  here so it is not reinvented: a **small, fixed, explicitly allowlisted set of version commands**
  (each its own entry, its own `reason_id`, its own constant argv — `sshd -V`, `openssl version`,
  and so on), with `confirmed` reachable **only for the packages those entries cover** and
  `highly_likely` everywhere else. That stays inside §5.1 because the argv is still a constant. It
  is not in Alpha.
  The scanner still records `detection_methods[]` with independence classes from the first finding
  (docs/23 item 8's shape, designed in rather than retrofitted) — the classes are honest about
  there being one method, which is the point.
- The corpus: **snapshots recorded from the Step 3 lab boxes**, never hand-written — and per the
  artefact rule, a case that asserts "the collector could not read X" must contain a snapshot in
  which X's section is present with status `error`, not a snapshot missing the section. That is the
  D67 check written into the corpus from the start.

---

## 10. What this spec deliberately does not decide

- **The fleet's OS and Python mix** — the operator confirms or corrects §3's assumption before Step 4,
  from the **fleet probe** (plan task A5), which he runs. If the floor rises to 3.8, §3.1's cost
  disappears. Until the probe comes back, the 3.6 floor stands as a *stated assumption*, in one
  constant, with §3.1's costs recorded. **Linux-only is not on this list: the operator confirmed it
  (§3).**
- **Which distributions Alpha supports.** The operator's instruction, 2026-10-13: **do not restrict
  Alpha's distribution support yet** — that decision waits on A5's results. The Debian licence
  question (§7.3) is separate and he is asking the Debian security team directly.
- **Signing the snapshot or the receipt.** That is docs/23 item 7 (scan receipt), whose cost note
  says signing is the part to scope carefully before committing. The snapshot format leaves room for
  a detached signature; nothing is signed in Alpha, and nothing claims to be verifiable yet.
- **Transport and enrolment.** No listener, no auto-update, no upload in Alpha (ADR-033, docs/26).
- **The always-on agent**, which is explicitly post-Alpha.

---

## 11. `agent/` as a new top-level directory — the alternatives, not just the outcome

CLAUDE.md says the only new top-level directories in this migration are `api/` and `web/`, and that
anything else STOPs and asks. So the decision is recorded with what it was weighed against, which is
what ADR-035 needs; the outcome alone would not satisfy the rule.

| Option | Why not |
|---|---|
| **`scanners/host/collector/`** — ship the collector inside the scanner | The collector runs on someone else's machine; the scanner runs on ours. Nesting it under `scanners/` makes the stdlib-only, 3.6-floor, no-`core/`-import rules a property of a subdirectory of a package that violates all three, and the import test becomes a rule about a path rather than about a boundary. It also implies the scanner may import the collector, which must never happen. |
| **`core/agent/`** | `core/` is the platform's shared services and is imported by everything. Putting ship-to-host code there inverts the dependency the design depends on: the collector must be unable to reach `core/`, and no test phrased as "`core/x` may not import `core/y`" is credible for long. |
| **`tools/agent/`** | `tools/` is the register of third-party tools we wrap and their licences. The collector is ours; filing it there confuses provenance, which is the one thing `tools/` is for. |
| **A separate repository** | Honest about the boundary, and the right answer eventually. Today it costs a second CI, a second review path and a version-skew problem between collector and scanner in the same release — for Alpha, where the two are designed and gated together. Recorded as the likely post-Alpha move, so this is reversible rather than permanent. |
| **`agent/`, a new top-level** — chosen | The boundary is the point: a directory whose whole contract is "standard library only, 3.6 syntax, imports nothing from this repo but itself". That contract is testable at the directory level (§3.2), reviewable by reading one directory, and visible to anyone who looks at the repo root. A thing that ships to other people's machines should be visible at the top level, not buried. |

**Cost accepted:** one more top-level directory, and CLAUDE.md's list needs updating alongside
ADR-035 (not a silent third entry). **Not a precedent:** the next new top-level directory asks
again.
