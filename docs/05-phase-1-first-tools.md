# 05 — Phase 1: The first four tools

*Four scanners, built one at a time, each finished before the next begins. All Light mode plus the Standard checks that are still passive.*

**Why this order:** cheapest and most deterministic first. Email and TLS have near-zero legitimate false-positive rates, so if our precision is poor there, the problem is the harness, not the domain. Prove the machinery on easy ground before Phase 2's genuinely hard work.

**Definition of done, for every tool in this phase:**

- [ ] Passes its accuracy gate on the corpus, in CI — **precision, recall *and* inconclusive rate**, computed per [10-measurement.md](10-measurement.md)
- [ ] Every finding carries structured evidence a user could verify themselves
- [ ] Ambiguous cases return `inconclusive`, never a guess and never a crash
- [ ] Zero findings against the known-good control targets
- [ ] Corpus entries committed: at least one positive and one negative per `check_id`
- [ ] Runs offline from recorded fixtures (`--replay`), so tests are deterministic
- [ ] `remediation` text is specific enough to act on without a web search
- [ ] Every check declares an `independence_class` and a hand-assigned prior with a one-line justification
- [ ] **Run against real targets and hand-verify every finding** ([ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done)) — the corpus proves internal consistency, not correctness. Record the result in [14-progress-ledger.md](14-progress-ledger.md): how many targets, how many findings, how many verified.
- [ ] Any Standard-mode check has an authorisation path: it refuses to run against a target absent from `config/authorised_scope.yaml` ([09-ownership-verification.md](09-ownership-verification.md))

---

## Tool 1 — Email Security Scanner

**Gate: precision ≥ 0.99, recall ≥ 0.95.**

The ideal first tool: pure DNS, entirely passive, RFC-defined correct answers, legally safe on any domain, and most companies genuinely fail it. High value per unit of effort.

### Light mode checks

| check_id | What |
|---|---|
| `spf-missing` / `spf-invalid` | SPF record present and syntactically valid |
| `dkim-missing` | DKIM selector detection |
| `dmarc-missing` | DMARC record present |
| `dmarc-policy-none` | Policy is `none` (monitoring only, does not stop spoofing) |
| `mx-missing` | MX records and mail provider identification |
| `spoofing-possible` | The summary verdict: can someone send mail as this domain |

### Standard mode adds (still passive)

| check_id | What — and the detail that makes it correct |
|---|---|
| `spf-lookup-limit` | SPF permits **10 DNS lookups**; exceeding it makes SPF fail entirely. Must resolve `include:` chains recursively to count. Very commonly broken and almost never detected. |
| `spf-too-permissive` | `+all` or `?all` |
| `dkim-weak-key` | Key strength below 1024/2048 bits |
| `dmarc-alignment` | Strict vs relaxed, `adkim`/`aspf` |
| `dmarc-no-rua` | No reporting address configured |
| `dmarc-pct-partial` | `pct<100` — policy only partially applied |
| `bimi-*`, `mta-sts-*`, `tls-rpt-*` | Presence and validity |
| `mail-tls-weak` | Mail server TLS configuration |
| `open-relay` | Open relay test — **connect and test the handshake only; never actually relay a message** |
| `lookalike-domain` | Typosquat permutations, checked for registration |

### Mechanism

1. Query TXT at `domain`, `_dmarc.domain`, `selector._domainkey.domain`; MX at `domain`.
2. Parse each against its RFC (SPF: 7208, DKIM: 6376, DMARC: 7489). Write real parsers — regex will be wrong on `include:` chains, macros, and qualifiers.
3. Simulate the receiving mail server's decision on a spoofed message; that simulation *is* the `spoofing-possible` verdict.
4. Typosquats: generate permutations (character swap, omission, insertion, homoglyph, TLD swap), check registration via RDAP.

### Evidence

The raw TXT record string, the parse tree, the resolved `include:` chain with its lookup count, and the simulated receiver decision. All of it is text — cheap to store, trivially verifiable by the user.

### Corpus

- **Positive:** fixtures with `p=none`, `+all`, an 11-lookup include chain, missing DMARC, weak DKIM key
- **Negative:** a domain with `p=reject`, aligned, under the lookup limit, DKIM 2048-bit
- **Frozen:** recorded DNS answers for ~50 real domains, hand-labelled once

### Gotchas

- DNS wildcards can make every `_dmarc.*` lookup appear to succeed — detect wildcards first or every finding is wrong.
- Multiple TXT records at one name is a **misconfiguration**, not a parse error. Report it.
- The 10-lookup limit counts `include`, `a`, `mx`, `ptr`, `exists`, `redirect` — not `ip4`/`ip6`. Getting this wrong is the classic bug.
- Some providers return `SERVFAIL` under load. That is `inconclusive`, not "record missing." This distinction is the whole difference between a trustworthy and an untrustworthy scanner.

---

## Tool 2 — SSL/TLS Analyzer

**Gate: precision ≥ 0.98, recall ≥ 0.95.**

`badssl.com` is effectively a purpose-built ground-truth corpus — dozens of subdomains each broken in exactly one known way. Use it heavily.

### Light mode

Certificate validity, expiry and days remaining, issuer, hostname match, chain completeness, self-signed/untrusted warning.

### Standard mode adds

Supported protocol versions (flag SSLv3, TLS 1.0, TLS 1.1), cipher suite enumeration with weak-cipher flags, Perfect Forward Secrecy, HSTS presence and quality (`max-age`, `includeSubDomains`, `preload`), Certificate Transparency presence, key strength and signature algorithm, known TLS vulnerabilities (Heartbleed, POODLE, ROBOT, etc.), and an overall **A+ to F grade**.

### Mechanism

Open TLS connections on 443 and any other TLS ports discovered; read certificate and full chain; then repeatedly renegotiate with different protocol versions and cipher lists to enumerate what the server accepts. Compare against a maintained best-practice baseline.

### Implementation choice

Start by **shelling out to `testssl.sh`** and parsing its JSON. **Pin the version tightly — its JSON schema has broken between minor releases (3.0 → 3.2).** Budget ~1–3 minutes per host for a full scan (`--fast` skips vulnerability checks); that cost shapes how many hosts a scan can cover. It is GPLv2, so **separate process only** — never linked, never copied into our tree ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves)). This gets a correct tool shipped fast.

Replace it with our own implementation when its runtime becomes the bottleneck. testssl.sh is thorough but slow, and the grading logic is ours regardless. Note in `tools/registry.yaml` as `subprocess`, and let the CI GPL check enforce it.

### Gotchas

- Vulnerability checks that require *sending malformed input* (Heartbleed) sit close to the [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) line. Detect by **version and configuration inference** where possible; if an active probe is genuinely required, it must be non-destructive, read-only, and documented in the tool registry with an explicit note.
- Grade is our opinion, not a fact — expose the full rubric so a user can see why they got a B.
- SNI, and hosts serving different certs per SNI name, are common. Test per hostname, not per IP.
- Expiry within 30 days is a finding; within 7 days it is a high-severity one.

---

## Tool 2.1 — The deprecation clock on TLS *(new in v3.4)*

**Gate: unchanged from Tool 2 — precision ≥ 0.98, recall ≥ 0.95.** Reported with its detected/derived split, per [10-measurement.md](10-measurement.md).

The first dated findings, on a scanner that already passes. Small, and it makes the pitch demonstrable in one command.

### Checks

| check_id | What | Derivation |
|---|---|---|
| `tls-cert-lifetime-excessive` | The certificate is longer than the maximum issuable from a published date | `derived` — from the certificate we already parse |
| `tls-renewal-cadence-at-risk` | Lifetime implies a renewal frequency the current process is unlikely to survive | `derived` |
| `tls-no-post-quantum-key-exchange` | The server does not offer hybrid PQ key exchange, so today's traffic is harvestable | `detected` — a real handshake |
| `tls-post-quantum-cdn-only` | The edge offers PQ but the origin does not | `detected`, needs the asset graph |

### The calendar this rests on

CA/Browser Forum ballot **SC-081v3**, passed April 2025 (29–0): maximum certificate validity **200 days from 15 March 2026**, **100 days from 15 March 2027**, **47 days from 15 March 2029**.

**Verify this against the ballot text before it reaches a customer or a slide.** The figures here came from secondary sources during research. The v3.1 review found ~25 defects by checking claims against primary sources, and a deprecation clock that cites a wrong date is worse than no clock.

### Prerequisites

Post-quantum checks **cannot run on the current toolchain** — verified, not assumed: `ssl.SSLContext.set_groups` does not exist on Python 3.12, and ML-KEM needs OpenSSL 3.5+. Task 0b.5. The lifetime checks have no such blocker and could ship first.

### Gotchas

- **A long certificate is not a vulnerability today.** It is an operational risk with a date. Severity is what it will cost *when it lands*; the date does the prioritising. Getting this framing wrong turns the flagship feature into a false positive with a countdown.
- **Absence of PQ support is not always the customer's fault or fix** — it is frequently the CDN's, or their origin's. Say which.
- **The `47 days` figure is the headline and 2029 is far away.** The one that bites first is 200 days, already in force.

---

## Tool 4 — Website & AI Exposure (Light) *(scope widened in v3.4)*

**Gate: precision ≥ 0.95, recall ≥ 0.85 — corpus-relative, never absolute.**

The original scope — headers, cookies, technology fingerprint, directory listing, information disclosure — is commodity; every competitor ships it. It stays, because it is the price of entry. What is added is the half nobody has productised.

### The AI and agent exposure half

Passive detection of AI infrastructure that was never meant to face the internet:

- exposed **MCP servers** — the plumbing that connects an AI assistant to tools and data
- agent **admin panels and debug endpoints**, frequently bound to every interface by default
- unauthenticated **model endpoints**
- **plaintext HTTP** on any of the above, which exposes OAuth tokens and API keys in transit

**Why this fits us rather than being a stretch.** It is fingerprinting — a port, a path, a response shape. No exploitation, so [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) holds without an exception. It is the same observe-and-evidence shape as everything already built, and it is new enough that we are not fighting a funded incumbent.

### The line we do not cross

**Finding an exposed server is passive. Reading what is on it is not.** One HTTP request separates them, and the difference is the whole of ADR-004. Light mode reports *that* an endpoint is exposed and unauthenticated. It does not enumerate the tools an agent can call, and it never reads a conversation history — even though both would be trivially possible, and precisely because they would.

This is why passivity becomes a per-check declaration in task 0b.6 rather than a mode assignment someone remembers to file correctly.

### Prerequisites

HTTP record/replay (0b.4) and the asset graph (0b.2). Neither is optional: without replay there is no deterministic corpus, and without discovery there is nothing to scan.

### Gotchas

- **This surface is young and moving.** Fingerprints will rot faster than DNS or TLS ones. The corpus needs re-recording on a schedule, and a stale fingerprint that stops matching is a silent recall loss, not a visible failure.
- **A default-configured local tool is not a finding.** Something bound to `127.0.0.1` on a developer's laptop is not exposed. Reachability from outside is the check, not the presence of software.
- **Recall is corpus-relative here**, same as DNS enumeration, and for the same reason: nobody knows the true set.

---

## Tool 3 — DNS & Subdomain Enumeration (Light)

**Gate: precision ≥ 0.95, recall ≥ 0.80 against the corpus's known set.**

Recall is measured against known-set-in-corpus only — "all subdomains that exist" is not a knowable quantity, and claiming otherwise would be dishonest.

This tool matters disproportionately because **it produces the asset list every other tool scans.**

### Light mode

Subdomains from Certificate Transparency logs and passive DNS; all record types (A, AAAA, MX, TXT, NS, CNAME, SOA); WHOIS/RDAP registration; nameservers; DNSSEC status; domain expiry.

### Standard mode adds

Active brute-force with a wordlist; liveness check per subdomain; per-subdomain technology detection; **subdomain takeover detection**; AXFR zone transfer check; wildcard DNS detection; related-domain discovery (same registrant, same cert, same IP block); OSINT harvesting; shadow-IT discovery.

### Build subdomain takeover detection early

Even though the rest of Standard mode is Phase 3. It is easy to detect reliably, genuinely dangerous, and it is the finding that makes a user say *"I did not know that was there"* — which is the moment they become a customer.

Mechanism: a CNAME points at a cloud service (S3, Azure, Heroku, GitHub Pages, Fastly, Shopify…) that is no longer claimed. Match the response against a maintained fingerprint list. **Never claim the resource to prove it** — that is [ADR-004](02-decisions.md#adr-004--no-exploitation-ever) territory. Fingerprint match plus an unclaimed-service signature is `highly_likely`; only an explicit provider API confirming the resource is unregistered makes it `confirmed`.

### Tools

`subfinder` (passive), `dnsx` (resolution and brute-force), `httpx` (liveness and metadata), CT log APIs (crt.sh). `Amass` for Standard only — it is thorough but slow.

**Free-tier recall is materially lower.** subfinder works out of the box against free public sources, but meaningful volume needs paid API keys (Censys, SecurityTrails, VirusTotal). The gap between free-tier and keyed configuration is large and must be **measured against the corpus, not assumed away** — it determines whether Light-mode enumeration is credible at all. A passive-DNS provider (Censys / SecurityTrails) is a paid data subscription, which is acceptable ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves)) but needs budget sign-off — see [07-open-questions.md](07-open-questions.md).

### Gotchas

- **Wildcard DNS makes brute-force return everything.** Detect wildcards first, by resolving a random name that cannot exist. Skipping this produces thousands of fake subdomains and is the single most common way enumeration tools embarrass themselves.
- CT logs contain names that never existed publicly or died years ago. Always liveness-check before reporting as an asset.
- Discovered subdomains are **not automatically in scope**. Enumeration is passive and allowed; scanning what it finds requires ownership verification for each asset. `core/authz.py` enforces this, and the distinction is legal, not stylistic.

---

## Tool 4 — Website Scanner (Light)

**Gate: precision ≥ 0.95, recall ≥ 0.85 (corpus-relative), inconclusive ≤ 0.15.**

**Recall here is corpus-relative, not absolute** — "all header misconfigurations on a site we don't fully understand" is not a knowable set, the same caveat that applies to subdomain enumeration. Never publish this number as if it were absolute. See [10-measurement.md](10-measurement.md).

Passive only. **No payloads are sent in this phase.** This is the reconnaissance half of the flagship; the active half is Phase 2.

### Checks

Server software and version; missing or weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy); insecure cookie flags (`Secure`, `HttpOnly`, `SameSite`); directory listing enabled; information disclosure in error pages, headers and comments; technology stack detection (CMS, framework, JS libraries, server); outdated component detection by version; robots.txt and sitemap review; a TLS summary reusing Tool 2.

### Two pieces of real engineering

**Technology fingerprint database v1.** Ours, Wappalyzer-style. Header patterns, cookie names, HTML/script markers, path probes. Structure it as data from the start — this database grows for years, and its accuracy governs the CVE matching that depends on it.

> **Licence guardrail.** Wappalyzer went closed-source in Aug 2023 and its pre-close fingerprint data — plus the community forks carrying it — is **GPL-3.0**. "Wappalyzer-style" describes the *approach*, not a licence to their data. Signatures must be authored from our own observation and public documentation. Do not copy or adapt those JSON files, which are widely mirrored and very tempting to bootstrap from.

> **Resourcing reality.** Nobody on a two-person team is a full-time fingerprint-database maintainer, and signatures rot as frameworks and bundlers change. Budget ongoing part-time maintenance rather than treating this as a one-off Phase 1 task, and **drop the "more accurate than Wappalyzer" claim** — it is unmeasurable and unearned.

**CVE matching with backport awareness.** Not fully built until Phase 2, but the trap starts here: **version strings lie**, because distributions backport security patches without changing the version. Reporting "Apache 2.4.41 has CVE-X" when Debian patched it months ago is the classic false-positive generator that makes users distrust a scanner.

Rule from day one: a version-only finding is capped at `suspected` and `confidence ≤ 0.6`. Cross-check distribution security trackers before going higher.

**Prerequisite the plan originally omitted: OS/distro fingerprinting.** You cannot query the right security tracker without knowing who packaged the software, and `Apache/2.4.41` does not say. Budget that detection explicitly (Phase 2). And note the limit: for software not packaged by a distro — custom builds, most language-ecosystem dependencies — no tracker exists and the version string genuinely is the only signal. There, the confidence cap is the *only* mitigation, permanently.

### Gotchas

- CSP is not present-or-absent. A CSP with `unsafe-inline` and `unsafe-eval` is close to worthless; grade quality, not presence.
- Missing headers on a static asset endpoint are not the same finding as missing headers on an authenticated page. Record `location` precisely.
- WAFs and CDNs alter or add headers. Detect the CDN and say so, rather than crediting or blaming the origin.
- Anti-bot pages return 200 with a challenge body. Detect that and return `inconclusive` for the whole scan rather than fingerprinting the challenge page as the customer's technology stack.

---

## Also in this phase

### Payload library v1 (structure only)

No Light-mode check sends a payload, but the format is established now so Phase 2 does not invent it under pressure.

```
payloads/
  sqli/boolean/or-1-1-v3.yaml
```
```yaml
id: sqli/boolean/or-1-1-v3
class: sqli
technique: boolean
payload: "' OR '1'='1"
control:  "' OR '1'='2"      # the paired negative — mandatory
expects:  response_differs
safety:   read_only          # never state-changing
severity_if_confirmed: critical
references: [...]
```

Every payload is **versioned and paired with a control**. The library's quality directly determines how many real bugs we find, so it is a maintained product asset with an owner — not a config file.

### Merged multi-tool scan

- [ ] `scan all --target example.com --mode light` runs all four, merges into one `ScanResult`, deduplicates by finding `id`, sorts by `severity_weight × confidence`

This is the first moment the product's core promise is visible from a terminal, and it is the exit criterion for Phase 1.

---

## Suggested sequencing

| Weeks | Work |
|---|---|
| 1–2 | Tool 1 (Email) — including the corpus discipline, which is new. Expect the first tool to take longer than its complexity suggests. **Its Standard-mode checks (SPF chain resolution, open-relay test) are the first that touch a real third party, so the ownership-verification file must work before they run.** |
| 3 | Tool 2 (TLS) — fast, since testssl.sh does the protocol work |
| 4–5 | Tool 3 (DNS/subdomain) + takeover detection |
| 5–6 | Tool 4 (Web Light) + fingerprint database v1 |
| 6 | Payload library structure, merged scan, phase review |

Review at the end: did the contract survive four real tools without changes? If it did not, fix it **now** — this is the last cheap moment to change it.
