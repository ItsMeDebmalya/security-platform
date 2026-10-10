# DomScout — DNS & Subdomain Enumeration (Tool 3, Light mode) — Design

*Design spec. Working artifact for the implementation plan, not part of the canonical doc set
(`SPEC.md` / ADRs / roadmap remain authoritative — this feeds changes into them, it does not
replace them). Date: 2026-09-03.*

Scanner name: **`domscout`**. Directory: `scanners/domscout/`.

---

## 1. What this is, and the one decision it exists to settle

DomScout is **Tool 3, A4** — the scanner that produces the asset list every later tool scans. It
is the **first scanner to *discover* assets onto the shared asset graph** (`core/assetgraph.py`,
ADR-019) rather than reading a graph seeded for it.

The blocking decision, settled before any code (per the ledger's "Next" and SPEC A4): **how recall
is defined when "all subdomains that exist" is unknowable.** Publishing a corpus-relative number as
if it were absolute is the specific dishonesty this product exists to avoid.

> **⚠️ SUPERSEDED during implementation (2026-09-03).** The two-number recall model below did not
> survive contact with the code: subdomain enumeration findings are honestly `severity: info` →
> `informational`, which `core/state.py`/`docs/10-measurement.md` exclude from precision/recall
> entirely — so there is no "enumeration recall" to gate. The operator and coordinator settled the
> honest model instead: **enumeration is informational inventory, not confidence-scored and not
> recall-gated; the gate applies only to the real security findings (DNSSEC/expiry/takeover), and
> enumeration completeness is assessed *live* against subfinder/crt.sh as a comparison, never a
> score.** See the ledger's 2026-09-03 Tool 3 entry. The rest of this spec stands; only this §1
> decision was replaced. Kept here unedited as the record of what was originally settled.

**Originally settled (superseded — see the note above): recall is reported as two separate numbers, never merged into one.**

- **Enumeration recall** — for subdomain *discovery*, the denominator (every subdomain that
  exists) is unknowable. We can only measure against the subdomains we deliberately planted in our
  own corpus. This is a real regression fence but **not a statement about the world**. Always
  labelled `corpus_relative`. The roadmap's **recall ≥ 0.80** gate binds this number.
- **Finite-check recall** — for checks with a knowable per-target answer (DNSSEC present or not,
  domain expiry date, dangling-CNAME on a *given* name), the denominator is knowable exactly as it
  is for email/TLS. This is **true recall** and is reported as such.

`make corpus` prints these on **separate lines** so neither can be read as the other. This mirrors
`docs/10-measurement.md`'s DNS row ("Recall against the corpus's *known* set only. Never a claim
about completeness") but sharpens it: only the enumeration family is corpus-relative; the finite
checks are held to true recall.

**Why the split matters (the failure mode):** a dishonest tool finds 30 subdomains, defines "all
subdomains" as "the 30 I found", and prints recall 100%. Lumping a finite DNSSEC check in with
unknowable enumeration under one "recall" number is the first step toward that lie. Keeping them
apart makes the honest limit visible on every run.

---

## 2. Scope — what ships in this Light build

Passive checks only (all cross-checkable against a free tool, which is deliberate — see §6):

| check_id (draft) | What it does | Data source (via `ctx`) | Free-tool comparison |
|---|---|---|---|
| `subdomains-ct-log` | Enumerate subdomains from Certificate Transparency logs | crt.sh over `ctx.http` | crt.sh, subfinder |
| `dns-records` | Resolve A/AAAA/CNAME/MX/NS/TXT/SOA for apex + each discovered name | `ctx.dns` | `dig`, dnsdumpster |
| `dnssec-status` | Delegation validation state: `signed` / `insecure` / `bogus` / `inconclusive` (see §10.2) | `ctx.dns` (DS, DNSKEY, RRSIG) | dnsviz, Verisign debugger |
| `domain-expiring` / `domain-expired` | Registration expiry via RDAP; `domain-expiring` is a **dated** finding (`materialises_at` = expiry date, threshold ≤ 30 days — §10.3) | RDAP over `ctx.http` | any WHOIS/RDAP |
| `subdomain-takeover` | A discovered name CNAMEs to a decommissioned service whose fingerprint we recognise. **DNS-only where possible** (CNAME target is NXDOMAIN); one ordinary HTTPS GET only when the service needs a body fingerprint | `ctx.dns` (+ optional ordinary HTTPS GET) | subjack, nuclei takeover templates |

**Every discovered subdomain that resolves definitely is contributed to `ctx.assets`** with
mandatory provenance. This is DomScout's unique job.

**Deliberately out of scope (Standard, a later build):** active brute-force (wordlist guessing),
AXFR zone-transfer probing, liveness/HTTP probing of every subdomain, per-subdomain tech
fingerprinting, related-domain/OSINT harvesting, commercial passive-DNS feeds (SecurityTrails et al.
— they require paid API keys, which collides with "never store customer secrets" and the free Light
tier). crt.sh is free and fully replayable offline.

---

## 3. Architecture & data flow

`scanners/domscout/{__init__.py, scanner.py, checks.py}`, following email/TLS exactly. Optional
pure parser modules (`ct.py`, `rdapp.py`, `takeover.py`) as they earn their place, each pure and
separately tested before anything touches the network — the same discipline as the email RFC
parsers. Class declares `name = "domscout"`, `version = "1.0.0"`, **`supported_modes =
frozenset({"light"})`** (this build is Light-only; the §2 out-of-scope Standard checks are a later
version bump), `target_types = frozenset({"domain"})`, and `requires_authorisation(mode)` returning
`False` for every mode (all checks passive) — mirroring `scanners/email/scanner.py:63-66`.

`run()` (one pass, mirrors `_Scan` in the email scanner):

1. **Wildcard-detect the apex zone** — `DnsClient.has_wildcard(domain, "A")` and for CNAME. This is
   stop-the-line: a zone with a wildcard answers every random name, so a CT-log name "resolving"
   proves nothing there. Presence is downgraded under a wildcard; **absence still stands** (a real
   answer beats a wildcard), exactly as the email scanner already reasons.
2. **Seed candidates from CT logs** — GET crt.sh JSON for the apex over `ctx.http`, parse out unique
   names under the apex. Passive, replayable, redaction-safe (no secrets in CT data).
3. **Resolve** each candidate + apex through `ctx.dns`. A name answering **definitely**
   (`is_definite()`, records present) → contributed to `ctx.assets`. SERVFAIL/timeout →
   `inconclusive`, never "does not exist".
4. **Finite apex checks** — DNSSEC (DS/RRSIG/DNSKEY), domain expiry (RDAP over `ctx.http`).
5. **Dangling-CNAME takeover** — for each resolved CNAME whose target matches a known-service
   fingerprint, one ordinary HTTPS GET; if the service returns its "no site here" body fingerprint,
   emit `subdomain-takeover` at **`suspected`** (capped — see §5). Never register/claim the
   resource; that is exploitation and is forbidden (ADR-004).

`run()` obeys the contract: `ctx.check_alive()` before every network touch, `ctx.progress(...)`,
and `telemetry.checks_run` lists **every** check that executed with its outcome.

---

## 4. Discovery onto the asset graph (ADR-019)

**Contribution discipline — a resolving name is not automatically a scannable asset.** This is the
one genuinely open modelling question, and DomScout is the first producer, so it is settled here:

- Contribute to the graph **only names under the apex that resolve to an address** (A/AAAA), with
  `Asset.value` **canonicalized** (lowercased, trailing dot stripped) before construction. These are
  the hosts a later HTTP/TLS scanner can actually point at.
- A **CNAME whose target is a third-party host** (`blog.acme.com` → `acme.github.io`) is a
  *relationship*, not an independently scannable asset — it is recorded as a `RelatedAsset` on the
  relevant finding, **not** contributed to the graph as a scan target. (Dumping `acme.github.io`
  onto the graph would invite a later scanner to scan someone else's host.)
- An **MX target** (`mail.provider.example`) is likewise a relationship, not a graph asset.
- A **CT-log name that does not resolve** is an enumeration observation but **not** a live asset —
  it is counted for enumeration bookkeeping (§12) and never contributed to the graph.

For each qualifying name:

```python
ctx.assets.contribute(DiscoveredAsset(
    asset=Asset(type="domain", value="api.acme.com"),   # canonicalized
    discovered_by="domscout",
    evidence=<finding id if one was emitted, else a short "resolved A -> 1.2.3.4 via CT log" note>,
    check_id="dns-records",   # or subdomains-ct-log
))
```

- Provenance is structural: `DiscoveredAsset` has no defaults for `discovered_by`/`evidence`, so an
  asset without provenance cannot be constructed. We rely on that, not on remembering.
- **Discovery confers no authorisation.** The graph is data, not widened scope. A later scanner
  re-asks `core/authz.py` per asset. DomScout itself never calls authz for discovery (its checks are
  passive), and nothing in this scanner treats a graph entry as permission.
- Corpus replay uses the existing `seed_asset_graph()` seam; but DomScout is a **producer**, so the
  corpus mainly exercises the contribute path — a first for the graph, whose consume path alone has
  been exercised until now.

---

## 5. States, confidence, evidence, passivity

- **Passivity (ADR-023):** every check is passive — a CT-log read, ordinary DNS resolution, an RDAP
  read, and one ordinary HTTPS GET are all "what an ordinary client does". So DomScout needs **no
  authorisation in any mode**, like email and TLS today. Each check still *declares* `passive=True`
  explicitly (no default; 0b.6).
- **Version-strings-lie / caps:** `subdomain-takeover` caps at `suspected` — we detect the dangling
  fingerprint, we never prove the takeover by taking it, so it rests on one observation and one
  independence class. `dns-records` presence and `dnssec-status` are direct observations.
- **`domain-expiring` is `detected` AND dated — not `derived`.** `materialises_at` (dated) and
  `derivation` (detected/derived) are **orthogonal** fields (ADR-018 / 0b.1). `domain-expiring` is a
  direct observation of the RDAP expiry date, so `derivation="detected"`, confidence from the
  confidence engine, single independence class `rdap`, capping at `suspected` — structurally
  identical to TLS's `tls-cert-expiring-soon` (a detected, single-class, dated finding — *not* the
  derived `tls-vuln-beast`). It carries `materialises_at` = the expiry date and
  `materialises_reason`. It has **no** `derived_from` and needs no separate premise finding. The
  word "arithmetic" is deliberately avoided: a threshold on an observation is still a detected
  observation here; ADR-018's `derived` path (inherited confidence via `derived_from`) is used only
  by the correlation pass, never by this check. `domain-expired` is the same, present-tense (no
  `materialises_at`).
- **Evidence — control-vs-test pair required on every finding:**
  - DNS findings: `dns_evidence(...)`, control = the wildcard probe (already the house pattern).
  - CT-log / takeover HTTP: `capture_http_pair(...)`, redacted + size-capped.
  - DNSSEC: test = the signed/unsigned answer, control = an independent re-query (a *second
    observation*, not a claim of mathematical independence — the ledger's standing note that a
    verifier sharing the blind spot confirms nothing applies).
  - RDAP expiry: there is no natural control pair for a registry date, so the control is an
    independent re-query of the RDAP endpoint, and `control_rationale` states plainly that a
    registration date is a single-source attestation. **The every-finding-needs-a-control rule is
    not relaxed** (CLAUDE.md hard rule); `control_rationale` is exactly the contract's answer to
    "this observation has no natural control".
  - If a control is genuinely impossible, `control_rationale` must say why — empty is refused.
- **`inconclusive` is a correct answer:** wildcard-poisoned zone, SERVFAIL, RDAP unavailable, crt.sh
  timeout → `inconclusive` with `no_verdict_reason`, never a guess and never a silent drop.
- **State is derived** by `core/state.py`, never hand-set. `confirmed` needs validation to have run
  and passed via an independent method (e.g. second-resolver re-query).

---

## 6. The one core change: per-family recall in `core/measurement.py`

`make corpus` currently reports a single recall per scanner — `TierSummary.recall` is computed from
tier-aggregated `tp + fn` (`core/measurement.py:157`), with **no family dimension** on `Observation`,
`CaseScore`, or `TierSummary`. So a per-family split is a **structural change across the scoring
types, not a one-line tag** (confirmed by reading the module — the first review draft understated
this):

- **Family is derived from `check_id`, not stored on `Observation`/`Expected`.** A small classifier
  maps DomScout's enumeration checks (`subdomains-ct-log`, `dns-records`) to `enumeration` and the
  rest to `finite`; every email/TLS check maps to `finite` by default. This keeps `Observation` and
  `Expected` untouched (so their fixtures and numbers cannot move) and confines the change to the
  scoring path.
- `score_case` (which still has the per-key detail) partitions `tp`/`fn`/`fp` by family; `CaseScore`
  and `TierSummary` gain family-bucketed counts; `TierSummary` exposes `recall_enumeration` /
  `recall_finite` / `precision_enumeration` / `precision_finite`; `Gate` evaluates the DomScout gate
  as **two** family gates. This touches `score_case`, `CaseScore`, `TierSummary`, and `Gate` — plan
  for four types, not one field.
- **Gate targets, pinned** (removing the review's "its own targets" TBD): `enumeration` recall ≥
  **0.80**, `enumeration` precision ≥ **0.95** (roadmap A4). `finite` recall ≥ **0.95**, `finite`
  precision ≥ **0.95** — matching email/TLS, because the finite checks are a genuinely knowable,
  true-recall surface of the same kind. The roadmap states only one pair for A4 (≥0.95/≥0.80);
  reconciling it to name both families is part of §8's doc work, and the 0.80 is read as the
  enumeration floor (the hard, corpus-relative one).
- Guard test: email and TLS corpus numbers must be **numerically identical** before and after this
  change (every one of their checks classifies `finite`, and the single-family path must reduce to
  today's exact arithmetic).

**What an enumeration false positive is** (precision needs this pinned, per the review): an
apex-canonicalised name we report as a discovered subdomain that is (a) not actually under the apex
(a mis-parsed CT SAN like `example.com.evil.com`), (b) a wildcard artifact (a name that only
"resolves" because the zone wildcards — §10.5), or (c) reported as a *graph asset* while not
resolving to an address. A CT-only, non-resolving name counted in enumeration bookkeeping but
**correctly withheld from the graph** is not a false positive — that distinction is exactly why
enumeration hits and graph contributions are measured separately.

This is the only `core/` edit; scanner logic lives entirely in `scanners/domscout/`.

---

## 7. Testing & definition of done

**Corpus (frozen, offline via `core/replay.py`):**

- Positive **and** negative case for every check (how-to-add-a-scanner §0). Includes a planted
  **dangling** CNAME (fires) and a **non-dangling** CNAME to a live service (silent) — the negative
  is what gives takeover measurable precision.
- ≥ 1 `known_good` case where DomScout must report **nothing** (a clean apex). Anything reported
  there — including a `suspected` — is a false positive by definition.
- A wildcard-zone case proving CT-log names are **not** confirmed under a wildcard.
- An `inconclusive` case (SERVFAIL / RDAP-unavailable) asserted separately, excluded from the
  inconclusive-rate where a definite answer is not expected.
- Fixtures recorded once via `scan run domscout --target <t> --record ...`, then baseline updated.

**Cross-check against free tools (ADR-024) — first-class, definition of done:**

- A **disagreement analysis**, not a union-as-ground-truth. Run DomScout, `subfinder`, `crt.sh` and
  `amass` separately on the operator's own domains and report the set breakdown — `unique-to-each`,
  `intersection` — then hand-classify a sample of the disagreements (the other tools are also wrong
  sometimes; the union is `toolA + toolB`, not truth). Recorded the way
  `corpus/crosscheck/testssl.py` records the TLS second opinion. Not part of the gate (depends on an
  external tool being installed), but owed before "done". A name unique to a competitor is a
  candidate false negative to investigate, not an automatic bug.
- Licence line (ADR-024): we read a competitor's *output* to build a checklist and to hunt false
  negatives; we never seed our checks or fingerprints from their data. The takeover-fingerprint list
  is built from public first-party "no site here" strings and public advisories, not copied from a
  GPL tool's database.

**Live verification (ADR-017), before done:** run against `<operator domain A>`, `<operator domain B>`,
`<operator domain C>` (operator-owned, so authorisation-clean) and hand-verify. Add a DNSSEC-signed
reference domain (e.g. `internet.nl`) for the finite checks, which have knowable answers there. The
corpus proves regression, not correctness — six real defects have survived corpora at 1.000; a
competitor found the eighth.

---

## 8. Docs to reconcile (part of the work, not after it)

- **SPEC A4:** move dangling-CNAME **subdomain takeover to Light** (it is passive under ADR-023).
  Record the reconciliation; note the roadmap already lists takeover under Tool 3.
- **SPEC status table + roadmap:** flip A4 to shipped with its two-number recall stated and the
  claim count beside it.
- **Ledger:** append the Tool 3 entry (Built / Found & fixed / Decided / Deferred), and update the
  "Next" section. Keep the ledger current *before* starting whatever is next, per memory.
- If moving takeover to Light alters an ADR's wording, update the ADR and `docs/08-changelog.md`
  (ADR-002: a decision change is a migration, not an edit).

---

## 9. Open items to resolve during implementation

- **crt.sh reliability & rate limiting:** crt.sh is frequently slow/down. Every crt.sh and RDAP
  request goes through the existing `core/ratelimit.py` (the `for_resolver()`/`for_target()` split
  and adaptive backoff already built for Tool 1) and `ConcurrencyCap` — the scanner does **not**
  invent its own throttling. A **429 or 5xx or timeout → `inconclusive`** for that source, never a
  silent empty set ("inconclusive must not quietly mean 'whatever happened when 400 requests hit one
  service'"). A second CT source (e.g. certspotter's free API) may be added under the same
  passivity/replay rules if crt.sh proves too flaky, but start with crt.sh alone (YAGNI).
- **RDAP coverage:** RDAP is not universal across TLDs (esp. some ccTLDs — `.co.in`, `.in` need
  checking). Where RDAP is absent → `inconclusive` for expiry, not a WHOIS-scraping fallback in this
  build.
- **Takeover fingerprint list size:** ship a *small*, justified list (the handful of well-documented
  services — GitHub Pages, S3, Heroku, etc.), each with a public source, rather than a large copied
  list. Every fingerprint is a detection needing a positive + negative case, so the list grows only
  as fast as corpus cases justify it.
- **Independence classes:** at least `dns_resolution` (the answer), `ct_log` (crt.sh), `rdap`, and
  `http_fingerprint` (takeover GET). A CT-log name that also resolves is corroboration across two
  classes and may reach `highly_likely`; a name seen only in CT logs but not resolving is *not* a
  live asset and is not contributed to the graph.

---

## 10. Data model, normalization & verdict mapping

Added in revision after review — these were narrative before and are the parts most likely to drift
into subtle inconsistency. Everything here obeys the existing contract; nothing invents a new state
or a new evidence kind.

### 10.1 Internal data model

Pure objects, parsed before any judgement, mirroring the email scanner's RFC-parser discipline:

- `CandidateName` — a raw name from a CT log, pre-normalization (keeps the original presentation).
- `ResolvedName` — a `CandidateName` after canonicalization + DNS resolution, carrying its answers.
- `RegistrationInfo` — the structured RDAP result (`registrar`, `expiry`, `statuses`,
  `created`, `source="rdap"`); **findings derive from this**, so registrar/transfer-lock/age can be
  surfaced later without re-plumbing RDAP into finding logic.
- `TakeoverFingerprint` (Protocol) — one provider adapter (§10.6).

These feed `Finding.create(...)` and `DiscoveredAsset(...)`; they are not themselves contract types.

### 10.2 DNSSEC states

`dnssec-status` reasons over DS-at-parent + DNSKEY-at-zone + RRSIG, not the presence of one RRSIG in
one answer (the review's valid catch — absence of an RRSIG in a single response does not prove the
zone unsigned). States, mapped to canonical finding states:

| DNSSEC observation | Finding |
|---|---|
| No DS at parent, no DNSKEY | `insecure` (unsigned delegation) — a real finding, canonical state `suspected`/`highly_likely` per corroboration |
| DS + DNSKEY + valid RRSIG | signed = correct posture: either an **`informational`** finding or **no finding and the check records `CheckRun.outcome="clear"`** — `clear` is a check *outcome*, not a finding state |
| DS present but validation fails (missing/expired RRSIG, key mismatch) | `bogus` — a finding; **full bogus detection needs a validating resolver, so where we cannot validate we return the `inconclusive` state, not `bogus`** |
| SERVFAIL / timeout on the DNSSEC queries | `inconclusive` state |

The DNSSEC *observation* label (`signed`/`insecure`/`bogus`) is the delegation validation state the
finding **describes** — the operationally meaningful thing — and is distinct from the finding's
canonical `state`, which is always one of the five fixed values derived by `core/state.py`. The two
must not be conflated: "insecure" is what we say about the zone; `suspected` is how sure we are.

### 10.3 RDAP & the expiring threshold

- `domain-expired` — expiry date is in the past. Present-tense finding.
- `domain-expiring` — expiry within **≤ 30 days** (chosen, not configurable in this build; recorded
  as a decision to revisit, same discipline as the deprecation calendar's `STALE_AFTER_DAYS`). A
  **dated** finding: `materialises_at` = the expiry date, `materialises_reason` set. Severity keyed
  to proximity is out of scope; the date carries the urgency.
- RDAP absent for the TLD (some ccTLDs — `.in`/`.co.in` must be checked) → `inconclusive`, **not** a
  WHOIS-scraping fallback in this build.

### 10.4 CT name normalization (the `ct.py` parser contract)

Each rule gets a positive and a negative unit test:

- **Lowercase, strip trailing dot.** `API.Example.COM.` → `api.example.com`.
- **Strip a leading `*.`** and treat the remainder as the candidate; never treat `*` as a hostname
  label.
- **Reject any name not within the apex.** `example.com.evil.com` and `notexample.com` are
  discarded — a suffix match on labels, not a substring match.
- **IDNA/punycode:** canonicalize to A-label form internally; keep the U-label presentation as
  evidence.
- **Apex bookkeeping vs. discovery:** a cert bearing only `example.com` produces the apex for
  enumeration bookkeeping but is **not** emitted as a "discovered subdomain" and is not
  re-contributed as a discovery (the scanner must not rediscover its own seed).

### 10.5 Wildcard scope — stated exactly

`DnsClient.has_wildcard` (existing, single random label, returns `bool | None`, stores the probe as
control) is used as-is for the **apex zone**. Stated guarantee and limit for Light:

- We detect an **apex-level** wildcard (`*.example.com`) and downgrade *presence* findings for names
  that could be wildcard artifacts. **Absence findings still stand** (a real answer beats a
  wildcard).
- We do **not** guarantee detection of a **deeper-label** wildcard (`*.dev.example.com`) in this
  build — a known, stated limitation, not a silent gap. Probing every intermediate label is a
  Standard-mode concern.
- `has_wildcard` returning `None` (probe not definite) → the presence checks that depend on it are
  `inconclusive`, never assumed wildcard-free. (The review's multi-probe robustness idea is noted as
  a possible future `core/dns.py` enhancement; not adopted now because it changes a client both
  shipped scanners share, for a marginal Light-mode gain.)

### 10.6 Takeover provider adapters

```python
class TakeoverFingerprint(Protocol):
    name: str
    source: str          # public advisory / first-party string this came from (ADR-024 licence line)
    def matches_dns(self, cname_target: str) -> bool: ...
    def evaluate_http(self, response: CapturedResponse) -> FingerprintResult: ...
```

Ship a **small, sourced** list (GitHub Pages, S3, Heroku — the handful with well-documented, stable
"no site here" behaviour), each with a positive + negative fixture and a public source. The list
grows only as fast as corpus cases justify it. Fingerprints are built from first-party strings and
public advisories, **never copied from a GPL tool's database** (ADR-024).

### 10.7 Failure semantics (per external dependency)

| Event | Result |
|---|---|
| DNS `NXDOMAIN` | definite — the name does not exist; not an asset, not a finding |
| DNS `NODATA`/`NOERROR` empty | definite — name exists, no record of that type |
| DNS `SERVFAIL`/`REFUSED`/timeout | `inconclusive` for that check, `no_verdict_reason` set |
| crt.sh 429 / 5xx / timeout | enumeration seed `inconclusive`; other checks proceed on their own sources |
| crt.sh malformed / partial JSON | `inconclusive` for enumeration; log, never a partial silent set |
| RDAP 404 / TLD unsupported | expiry `inconclusive` |
| RDAP 429 / 5xx / timeout | expiry `inconclusive` |
| Takeover GET timeout / connection refused | takeover `inconclusive` (do **not** infer takeover from a failed GET alone) |

The resilience principle (review #3): **discovery and each enrichment fail independently.** crt.sh
being down does not make apex DNSSEC or RDAP expiry unknown; the run is not one unit of truth.

### 10.8 Observation → state mapping (state stays derived, never scanner-set)

This is a *mapping of observations to the inputs `core/state.py` already consumes* (confidence,
validation, independence classes), **not** a new state model. The five canonical states are fixed
(`confirmed`/`highly_likely`/`suspected`/`informational`/`inconclusive`).

| Observation | Independence classes | Validation | Resulting canonical state |
|---|---|---|---|
| CT-log name only, does not resolve | `ct_log` | none | not a finding; enumeration bookkeeping only |
| Name resolves (A/AAAA), no re-query | `dns_resolution` | none | `suspected` (single class) → graph asset |
| Name resolves + independent second-resolver re-query agrees | `dns_resolution` (validated) | passed | `confirmed` → graph asset |
| Name in CT **and** resolves | `ct_log` + `dns_resolution` | none | `highly_likely` (two classes) → graph asset |
| Dangling CNAME: target NXDOMAIN, fingerprint matches | `dns_resolution` | none | `suspected` (capped — never proven by taking it) |
| Dangling CNAME + HTTP body fingerprint | `dns_resolution` + `http_fingerprint` | none | `suspected`→ may reach `highly_likely`; still never `confirmed` |
| DNSSEC `insecure` (no DS/DNSKEY), re-query agrees | `dns_resolution` (validated) | passed | up to `confirmed` for the posture claim |
| Any source SERVFAIL/timeout/429/5xx | — | — | `inconclusive` |

`confirmed` still requires validation to have run and passed via an independent method — the table
never lets a scanner hand-pick it.

---

## 11. Reviewed recommendations — adopted, and rejected with reason

An external AI review (temp/domscout-spec-review.md) raised 14 points. Recorded here so the rejected
ones are not silently re-litigated during implementation.

**Adopted** (folded into this revision): CT normalization rules (§10.4), DNSSEC state truth-table and
`dnssec-status` rename (§10.2), RDAP `RegistrationInfo` + the ≤30-day expiring threshold as a dated
finding (§10.3), the `TakeoverFingerprint` adapter interface (§10.6), enumeration precision + an
explicit enumeration-FP definition (§6), disagreement-analysis cross-check over union-as-truth (§7),
the independent-failure/resilience principle (§10.7), asset-contribution discipline (§4), and an
explicit observation→state mapping (§10.8).

**Already handled by the existing platform — noted, not rebuilt:** rate limiting/backoff
(`core/ratelimit.py`, the `for_target`/`for_resolver` split; §9); the "no natural control" concern
(the contract's required `control_rationale`, not a new evidence-quality taxonomy; §5); graph dedup
(canonicalize `Asset.value`, but the one-`DiscoveredAsset`-per-provenance model is deliberate,
ADR-019 — not re-architected; §4).

**Rejected — conflicts with a settled ADR:**

- **A new capability-class taxonomy (`benign_validation` / `authorized_active`) making an ordinary
  HTTP GET require authorization.** Contradicts **ADR-023** (decided 2026-09-02: passive = ordinary
  negotiation, active = malformed input) and the competitive-baseline finding that gating ordinary
  checks behind authz was self-inflicted harm the market does not impose. An ordinary GET is passive
  here, full stop. The one grain kept: the takeover GET is to a *third-party* host, noted explicitly
  (§2), and much dangling-CNAME detection is DNS-only and needs no GET at all.
- **A scanner-defined state model (`observed`/`likely`/…).** State is computed by `core/state.py`
  and is one of five fixed values (hard invariant). The useful half — an observation→state table —
  is adopted in §10.8 in the contract-correct form.
- **Relaxing "every finding needs a control-vs-test pair".** This is the product's thesis and a
  CLAUDE.md hard rule; `control_rationale` is already the contract's answer for observations with no
  natural control (§5).
- **Moving takeover out of Light.** Overridden by an explicit product decision (takeover ships in
  Light, passive, detected-only) and the roadmap listing takeover under Tool 3. The adapter interface
  that made the "it's complex" point actionable is adopted anyway (§10.6).

**Second review (in-context, against the ADRs — verified against the code):** a follow-up review
with full repo context found four sound issues, all now fixed above: (1) §10.2 had let a signed zone
"report … or `clear`", reading as a sixth finding state — corrected to distinguish the DNSSEC
*observation* label from the finding `state` and to name `clear` as a `CheckRun` outcome; (2)
`domain-expiring` was described with "arithmetic on a date", which reads as ADR-018 `derived` —
pinned as `detected` + dated (orthogonal fields), mirroring TLS's `tls-cert-expiring-soon`, with no
`derived_from`; (3) §6 understated the `core/measurement.py` change — corrected to name the four
scoring types affected and the check_id-classifier approach; (4) the finite-family gate numbers were
"TBD" — pinned to recall ≥ 0.95 / precision ≥ 0.95. Its verification that the spec's claims about
`core/dns.py` (`has_wildcard`), `core/assetgraph.py`, `core/state.py`, and `core/authz.py` are
factually correct is on record; those claims stand.

---

## 12. Enumeration bookkeeping vs. graph contribution — the counting model

Two populations, deliberately not the same set, and this is why the recall split (§1) is honest:

- **Enumeration hits** — every canonicalised, in-apex name we surface from CT logs (whether or not
  it resolves). Measured against the corpus's *planted* set → `enumeration_recall` (corpus-relative)
  and `enumeration_precision`.
- **Graph contributions** — the strict subset that resolves to an address (§4). A CT-only
  non-resolving name is a legitimate enumeration hit and, correctly, **not** a graph asset; that is
  not a false positive.

A later consumer scans graph contributions, never raw enumeration hits — so a CT name that never
resolved can never cause a later scanner to touch a host that is not there.
```
