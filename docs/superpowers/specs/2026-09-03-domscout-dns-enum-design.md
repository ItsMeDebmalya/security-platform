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

**Settled: recall is reported as two separate numbers, never merged into one.**

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
| `dnssec-unsigned` | Zone is not DNSSEC-signed (no DS at parent / no RRSIG) | `ctx.dns` (DS, RRSIG, DNSKEY) | dnsviz, Verisign debugger |
| `domain-expiring` / `domain-expired` | Registration expiry via RDAP | RDAP over `ctx.http` | any WHOIS/RDAP |
| `subdomain-takeover` | A discovered name CNAMEs to a decommissioned service whose fingerprint we recognise | `ctx.dns` + one ordinary HTTPS GET | subjack, nuclei takeover templates |

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
parsers.

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

For each subdomain that resolves definitely:

```python
ctx.assets.contribute(DiscoveredAsset(
    asset=Asset(type="domain", value="api.acme.com"),
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
  independence class. `dns-records` presence and `dnssec-unsigned` are direct observations. Expiry
  is arithmetic on an RDAP date → a **dated** finding (`materialises_at` = expiry date) for
  "expiring", and a present-tense finding for already-expired.
- **Evidence — control-vs-test pair required on every finding:**
  - DNS findings: `dns_evidence(...)`, control = the wildcard probe (already the house pattern).
  - CT-log / takeover HTTP: `capture_http_pair(...)`, redacted + size-capped.
  - DNSSEC: test = the signed/unsigned answer, control = an independent re-query (second resolver).
  - If a control is genuinely impossible, `control_rationale` must say why — empty is refused.
- **`inconclusive` is a correct answer:** wildcard-poisoned zone, SERVFAIL, RDAP unavailable, crt.sh
  timeout → `inconclusive` with `no_verdict_reason`, never a guess and never a silent drop.
- **State is derived** by `core/state.py`, never hand-set. `confirmed` needs validation to have run
  and passed via an independent method (e.g. second-resolver re-query).

---

## 6. The one core change: per-family recall in `core/measurement.py`

`make corpus` currently reports a single recall per scanner. DomScout needs recall bucketed by a
**recall family** so enumeration (corpus-relative) and finite checks (true) print separately and are
gated separately. Proposed minimal change:

- A corpus case (or an expected entry) may tag its expected findings with a `recall_family`
  (`enumeration` | `finite`). Untagged → `finite` (the existing behaviour for email/TLS, so their
  output is unchanged byte-for-byte).
- `core/measurement.py` computes recall per family; the gate binds `enumeration` at ≥ 0.80 and
  `finite` at its own target. The printed table gains a family column / second line for DomScout
  only.
- Guard test: email and TLS corpus numbers must be **numerically identical** before and after this
  change (they carry no `enumeration` family).

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

- A comparison of DomScout's enumeration vs. the **union of `subfinder` + crt.sh** (and Amass for
  breadth) on the operator's own domains, recorded the way `corpus/crosscheck/testssl.py` records
  the TLS second opinion. Not part of the gate (depends on an external tool being installed), but
  owed before "done".
- Licence line (ADR-024): we read a competitor's *output* to build a checklist and to hunt false
  negatives; we never seed our checks or fingerprints from their data. The takeover-fingerprint list
  is built from public first-party "no site here" strings and public advisories, not copied from a
  GPL tool's database.

**Live verification (ADR-017), before done:** run against `codez.in`, `kinetrix.in`,
`kinetrix.co.in` (operator-owned, so authorisation-clean) and hand-verify. Add a DNSSEC-signed
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

- **crt.sh reliability:** crt.sh is frequently slow/down. If it times out → `inconclusive` for the
  enumeration seed, never a silent empty set. A second CT source (e.g. certspotter's free API) may
  be added under the same passivity/replay rules if crt.sh proves too flaky, but start with crt.sh
  alone (YAGNI).
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
```
