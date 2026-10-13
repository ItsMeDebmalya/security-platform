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
- `state` is computed by `core/state.py` as always; nothing is hand-set; `confirmed` needs validation
  to have run and passed, which for a host fact means a second, independent observation in the same
  snapshot (a package's version from the package database *and* the binary's own reported version,
  for instance) — which is docs/23 item 8's shape, so the scanner records
  `detection_methods[]` with independence classes from the first finding rather than being
  retrofitted.
- The corpus: **snapshots recorded from the Step 3 lab boxes**, never hand-written — and per the
  artefact rule, a case that asserts "the collector could not read X" must contain a snapshot in
  which X's section is present with status `error`, not a snapshot missing the section. That is the
  D67 check written into the corpus from the start.

---

## 10. What this spec deliberately does not decide

- **The fleet's OS and Python mix** — the operator confirms or corrects §3's assumption before Step 4.
  If the floor rises to 3.8, §3.1's cost disappears.
- **Which distributions Alpha supports**, which depends on the Debian licence question (§7.3).
- **Signing the snapshot or the receipt.** That is docs/23 item 7 (scan receipt), whose cost note
  says signing is the part to scope carefully before committing. The snapshot format leaves room for
  a detached signature; nothing is signed in Alpha, and nothing claims to be verifiable yet.
- **Transport and enrolment.** No listener, no auto-update, no upload in Alpha (ADR-033, docs/26).
- **The always-on agent**, which is explicitly post-Alpha.
