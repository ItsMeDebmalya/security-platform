# 06 — Guidelines

*Rules that apply to all code, all scanners, all phases. Most of these exist because breaking them is either illegal, or destroys the trust the product is built on.*

---

## Non-negotiables

These are not style preferences. Violating any of them is a stop-the-line event.

1. **No exploitation.** No code execution on a target, no state change, no data extraction, no brute-force, no load testing. Prove with out-of-band callbacks instead. ([ADR-004](02-decisions.md#adr-004--no-exploitation-ever))
2. **No active scan without verified ownership.** Standard and Deep modes require a valid, unexpired `authz_ref`, enforced in `core/authz.py`, deny-by-default. This is a legal requirement, not a product feature, and it applies from the very first Standard-mode check — not from Phase 6. Methods, lifecycle and audit record: [09-ownership-verification.md](09-ownership-verification.md).
3. **The kill switch always works.** Checked between every request. If a code path can send a request without checking it, that path is a bug.
4. **No GPL code in our tree.** GPL tools run as separate processes only. Never link, never copy, never adapt. The GPL tools are **testssl.sh, ScoutSuite and MobSF** — MobSF is GPLv3 and, being a Django app rather than a CLI binary, must run as its own containerised service talked to over HTTP, never imported. **GPL applies to data as well as code**: Wappalyzer's pre-2023 fingerprint database and its forks are GPL-3.0 and must not be copied into our fingerprint DB.
5. **Never store customer secrets.** Cookies, auth headers and anything matching a secret pattern are redacted **at capture time**, before anything is written to disk.
6. **Never say "compliant."** Only "compliance readiness." ([ADR-011](02-decisions.md#adr-011--compliance-readiness-never-compliance))

---

## Accuracy rules

The product is accuracy. These are the rules that produce it.

**Every finding needs a control.** "The server returned an error" is not evidence. "The server returned 47 rows for `1=1` and 0 rows for `1=2`, identical in every other respect" is. A detection without a paired control comparison is not shippable.

**`inconclusive` is the correct answer more often than you think.** Timeout, WAF block, rate-limited, ambiguous response, missing prerequisite — all of these are `inconclusive`. Never guess, never silently drop. Honest uncertainty is the fastest way to earn trust with experienced security people, and it is a feature no competitor ships.

**Version strings lie.** Distributions backport security patches without bumping versions. Any finding derived from a version string alone is capped at `state: suspected`, `confidence ≤ 0.6`, until a behavioural check or a distribution security tracker confirms it. This single rule prevents the largest category of false positives in the industry.

**Precision beats recall.** When trading off, choose precision. A scanner that misses things is disappointing; a scanner that cries wolf is worthless.

**A new detection means a new corpus case.** Both a positive and a negative. No exceptions — a detection with no negative case has no measurable precision. It also declares an `independence_class` and a hand-assigned prior with a written justification.

**State is computed, never chosen.** `core/state.py` derives it from confidence, validation outcome and method independence. A scanner that hand-sets `state` is a bug — the calibration promise depends on state being a reproducible function, not an author's judgement.

**Gates are three numbers, not two.** Precision, recall, and inconclusive rate. Excluding `inconclusive` without capping it lets a scanner score perfectly by shrugging at everything. See [10-measurement.md](10-measurement.md).

**Confidence is provisional until Phase 4.** Until calibration runs, values come from hand-assigned priors and must be flagged as such. Uncalibrated numbers presented as precise are worse than no numbers.

---

## Engineering rules

**The contract is frozen.** Changing `contracts/*.schema.json` after Phase 1 is a migration: versioned, reviewed, with a written migration path for stored findings. Not a casual edit. ([ADR-002](02-decisions.md#adr-002--freeze-the-scanner-contract-before-writing-tool-1))

**Scanners never construct their own clients.** HTTP, DNS, OOB and rate limiting all come from `ScanContext`. This is how safety guarantees stay guaranteed rather than remembered. If you need a client behaviour that `core/` does not offer, extend `core/`.

**Scanners never import from each other.** Shared logic moves to `core/`. A cross-scanner import is a refactor signal, not a shortcut.

**Bump `scanner_version` when results change.** Findings from different engine versions must remain comparable, and "did the target change or did we change?" must always be answerable.

**Everything is replayable.** Record traffic once, replay offline forever. Corpus tests that hit the live internet are slow, flaky, and rude to third parties.

**Third-party binaries are pinned by exact version and checksum**, and registered in `tools/registry.yaml` with their licence before first use.

**Count cost from the first scan.** Requests, wall time, AI tokens. Without this we will not know our margins until it is too late to fix them.

---

## Rate limiting and target safety

Our scanners talk to systems other people depend on. Being wrong here means outages, abuse complaints, and blocked IP ranges.

- **Token bucket per target host**, conservative by default.
- **Adaptive backoff.** Rising latency or 429/503 shrinks the bucket automatically. Back off before the target notices, not after.
- **Global concurrency cap per target organisation.** Scanning 50 subdomains in parallel must not become an accidental load test.
- **Never follow a redirect out of scope.** Never let an SSRF probe target a third party — the callback host is ours, always.
- **Publish our scanner IP ranges** so targets can identify us.
- **Honour a documented opt-out** for passive scanning of assets the requester does not own.

---

## Licence discipline

**The rule:** permissive OSS may be embedded; commercial, restrictive or legally-unclear tools may not — we build the capability ourselves and import their output instead. ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves))

**Before adding any dependency:**

1. Check its licence against the approved list in ADR-003.
2. Add it to `tools/registry.yaml` — version, licence, SPDX id, source, purpose, isolation mode, sign-off.
3. If GPL: mark `isolation: subprocess`. CI fails the build if a GPL entry is marked `library`.
4. If not clearly permissive: **do not add it.** Raise it as an open question instead.

**Specific traps:**
- **Nmap** cannot be shipped in a commercial product *even inside a container*. Use naabu. Note that naabu does port discovery **only** — it has no service/version detection, and our replacement for that is deliberately scoped to ~50 services, not Nmap parity.
- **Semgrep's rules** changed licence in Dec 2024 — unusable in a competing SaaS. Use Opengrep with our own rule corpus.
- **TruffleHog** is AGPL-3.0, which can require publishing our source. Use Gitleaks plus our own validator.

---

## Data handling

- **Evidence bodies are size-capped** (256 KB default; head + tail beyond that, with truncation marked explicitly).
- **Redact before storage.** Never after.
- **Customer code, container images and cloud credentials are the highest-sensitivity data we touch.** Clone and unpack in an isolated sandbox with restricted network egress. Cloud connections are read-only roles, never keys, never write access.
- **Every row carries `org_id`** from the first migration, even before multi-tenancy exists.
- **Never scrape criminal marketplaces or purchase stolen data.** Breach data comes from licensed providers only, after legal review.
- **Retention is not unlimited.** Evidence bodies purge at 90 days; authorisation records are kept 7 years. Full table in [11-operations.md](11-operations.md). Findings and evidence can incidentally contain customer production data and, in the case of OSINT, personal data about people who never consented.
- **Our own secrets** (data-provider API keys, AI keys, OOB auth, cloud external IDs) never enter the repo, logs, evidence, or error messages.

---

## Communication rules

How we describe findings is part of the product.

- **Impact in plain language.** "An attacker can read other users' orders by changing a number in the URL" — not "IDOR in `/api/orders/{id}`."
- **Remediation must be specific.** "Set `SameSite=Lax` on the `session` cookie" — not "review cookie configuration."
- **Never inflate severity to seem valuable.** Users notice, and it costs more trust than the finding was worth.
- **Every score is clickable down to the findings that caused it.** An unexplainable score destroys trust with technical users.
- **The AI assistant explains our evidence.** It never invents findings, never speculates beyond what the evidence supports, and says "the evidence does not show that" when asked something it cannot support.

---

## Pre-merge checklist

- [ ] `make test`, `make lint`, `mypy --strict core/` all green
- [ ] `make corpus` shows no precision regression on any scanner
- [ ] New detections have both a positive and a negative corpus case
- [ ] New dependencies are in `tools/registry.yaml` with a licence
- [ ] No new direct HTTP/DNS client construction outside `core/`
- [ ] `scanner_version` bumped if results changed
- [ ] Evidence for new findings is replayable and redacted
- [ ] Nothing added that sends state-changing requests to a target
- [ ] `state` is derived, not hand-set
- [ ] Inconclusive rate did not rise on the frozen corpus tier
- [ ] Zero findings on the known-good tier (a single one fails the build)
