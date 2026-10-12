# Alpha Scan Outcomes & Report Plan

**Project:** Integrated Security Platform (ProofScan → v4)
**Prepared:** 10 October 2026 · **Status:** Draft for review
**Scope basis:** MVP Alpha Scope v2 ([docs/24](24-alpha-scope.md)): one combined release with two parts, recorded in [ADR-033](02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred)
**Reconciled against [docs/21-scanner-catalogue.md](21-scanner-catalogue.md) on 12 October 2026, and again after the catalogue was regenerated from the code the same day.** Corrections are marked *(reconciled)*. The catalogue is generated from the code and wins on any data point.

---

## 1. Scan depth in the Alpha

| Track | Who | Depth | What it means |
|---|---|---|---|
| **Customer Alpha** | External invited users | **Light** for any domain; **Light + passive Standard** for an owner verified by DNS TXT ([ADR-033](02-decisions.md#adr-033--mvp-alpha-scope-one-combined-release-the-linux-agent-moves-into-alpha-tool-4b-deferred), decision 8) | Passive. Public information only: ordinary web requests (at most 12 page requests per scan, though redirect hops can add more until ledger D26 is fixed), DNS lookups, TLS handshakes. Nothing is changed on the target. No signed agreement needed; Standard needs proof of ownership. *(reconciled: the declared request cap does not yet count redirect hops)* |
| **Internal fleet** | Codezin's own servers | Light + **agent (PLANNED, not built)** | Everything above, plus a read-only agent on each host reading real package, patch and configuration state. Covered by one internal written authorisation. |
| *Deep / offensive* | *Not in Alpha* | — | *Staged after Alpha, gated by DNS-TXT verification and the signed agreement.* |

Every report states the depth it was produced at, so a Light report can never be mistaken for a full assessment.

---

## 2. Data points captured

The authoritative, per-check list is generated from the code in `docs/21-scanner-catalogue.md`. This section summarises it by area.

### 2.1 Per scanner

| Scanner | What it observes | Example outcomes |
|---|---|---|
| **Web** (all Light) | Security headers (HSTS, CSP, frame protection, content-type, referrer, CORS), HTTP→HTTPS redirect, mixed content, script integrity, version disclosure, error and debug pages, directory listings, technology fingerprint, robots.txt paths, security.txt, end-of-life components, secrets in served content | "No HSTS, confirmed on two responses"; "4 open directory listings"; "PHP 7.1 is past end-of-life (suspected)" |
| **Email, Light** | MX, SPF (missing, invalid, multiple records), whether a DKIM key is found among common selectors (`inconclusive` at most when none is: selectors cannot be enumerated, ledger D37), DMARC (missing, invalid, `p=none`, test mode; RFC 9989 reading; parent-domain discovery), spoofability, secrets in DNS records the scan read | "Domain can be spoofed: no enforcing DMARC"; "DMARC is monitoring only (`p=none`)" |
| **Email, Standard** *(verified owners only, ADR-033)* | DKIM key strength, SPF qualifier and lookup limit, DMARC reporting address, alignment, `pct`, `np=` and obsolete tags, MTA-STS, TLS-RPT | "DKIM key meets the 1024-bit minimum, below the recommended 2048"; "No MTA-STS policy, so mail delivery can be downgraded" |
| **TLS, Light** | Whether a handshake succeeds, certificate expired or not yet valid, expiry within 30 days, chain completeness, untrusted root, self-signed, hostname match (RFC 9525) | "Certificate expires in 9 days"; "Certificate does not cover the hostname" |
| **TLS, Standard** *(verified owners only, ADR-033)* | Key strength and signature algorithm, protocol versions, negotiated cipher and forward secrecy, Certificate Transparency proof, BEAST exposure (derived from the protocol finding). **Not in Alpha until D56 is fixed:** RC4, SWEET32, FREAK and LOGJAM, which come via testssl.sh and currently send active probes. Revocation is not checked at any depth (ledger D12) | "TLS 1.0 still accepted"; "Certificate key is under 2048 bits" |
| **Domain (domscout)** (all Light) | Subdomains from Certificate Transparency (crt.sh only, ledger D-DS1), DNS records, DNSSEC status of the zone the name belongs to, registration expiry from the registry's own RDAP server (reported only when within 30 days or past; "does not apply" for special-use names, ADR-032), dangling subdomains (takeover candidates on S3, Heroku and GitHub Pages), secrets in served content | "12 subdomains discovered"; "DNSSEC not enabled"; "Registration expires in 20 days (suspected)" *(reconciled: the check fires only within 30 days, so "40 days" could never be a finding)* |
| **Agent** *(internal fleet; **PLANNED, not built**)* | Installed packages and exact patch levels, OS and kernel end-of-life, running services, service configuration, file permissions on logs, backups and config | "OpenSSL is patched despite its version string"; "Backup file readable by the web server user" |

### 2.2 Recorded for every finding

| Field | Purpose |
|---|---|
| Check ID | Stable identifier, so findings can be tracked across scans |
| Severity | How bad it would be if true |
| Confidence | How sure we are, kept separate from severity |
| State | confirmed · highly likely · suspected · inconclusive · informational |
| Location | Where it was observed (path, record, host) |
| Description | Plain-language explanation, including the limits of the evidence |
| Evidence | The control-vs-test pair behind the claim: an HTTP request and response, a DNS answer, or a TLS handshake |
| Validation | How the claim was checked, and what that check does *not* prove |
| Redaction receipt | If a secret was found: its type and count, never the value |
| Remediation | What to change |
| Standard reference | The RFC or guideline the check is based on |

### 2.3 Recorded for every scan

Target and depth, start and end time, scanner versions, every check that ran with its outcome, requests sent, inconclusive rate, each inconclusive result with its reason, and each check that did not apply with its registered reason (ADR-032).

*(reconciled, from the code: a check that never ran because an earlier one could not get what it needed, such as `domain-expired` when the registry's record could not be read, is not recorded at all today. The first check's `inconclusive` finding says why. So "every check that could not run" overstated what is captured.)*

### 2.4 Deliberately not captured

- **Secrets.** Detected and reported by type, never stored.
- **Personal data about the organisation's people.** No employee names, emails or profiles.
- **Content beyond what's needed to prove a finding.** Directory listings are judged by filename; files are never downloaded.
- **Anything outside the declared scope.**

---

## 3. The structured report

### 3.1 Sections

**1. Cover**
Organisation name (as supplied by the customer), assets in scope, scan date, depth, report ID, confidentiality marking.

**2. Executive summary** (one page)
- Overall posture score with sub-scores by area
- Top risks, written for a non-technical reader
- **"Fix this first"**: the changes that close the most findings, e.g. *"Publishing an enforcing DMARC policy closes 4 findings"*
- What was not tested at this depth

**3. Scope and method**
Assets scanned, depth, date and time window, scanner versions, a one-paragraph method summary, and the standards the checks are based on.

**4. Asset inventory** (the target's details)
- Domains and discovered subdomains
- IP addresses and hosting or CDN provider
- Web technology observed (server, frameworks, CMS)
- Mail providers and mail-security setup
- Certificate issuers and expiry dates
- DNS hosting and DNSSEC status
- *(internal fleet, **PLANNED**)* Host OS versions, end-of-life status, key packages

**5. Posture by area**
One section each for Web, Email, TLS and Domain: a summary, a pass / attention / fail view of the key controls, and the findings in that area.

**6. Findings in detail**
One entry per finding with every field from 2.2, ordered by severity, then confidence.

**7. Coverage and limits**
Inconclusive results and the reason for each, checks that could not run, firewall-filtered tests, and known limits of the evidence. This section is what makes the rest credible.

**8. Appendix**
Glossary of states and severities, the full check list run, and evidence hashes so findings can be verified later.

*(Added after Alpha: compliance-readiness mapping to CERT-In, DPDP, ISO 27001.)*

### 3.2 Formats

| Format | Audience | Notes |
|---|---|---|
| **JSON** | Machines, integrations | The source of truth. Every other format is generated from it. |
| **HTML** | Dashboard, shared link | Interactive: expand a finding to see its evidence |
| **PDF** | Management, auditors | Executive summary first; print-ready |

### 3.3 Rules for how reports are built

1. **Deterministic.** The report is generated from stored findings. The same scan always produces the same report.
2. **AI writes summaries only.** Plain-language summaries may be AI-written, are labelled as such, and may not add, remove or change any fact. A test checks every summary against its findings.
3. **Every statement is traceable.** Each claim in the report links to a finding ID and its evidence.
4. **Uncertainty is shown, not hidden.** Suspected and inconclusive findings appear in their own clearly labelled places, and are never counted as passes.
5. **No secrets, no personal data.** Enforced by the same redaction as storage, and tested.

---

## 4. How findings are showcased

| Channel | What the viewer sees |
|---|---|
| **Dashboard** | Score, findings list, evidence on demand, and change since the last scan |
| **PDF report** | The full structured report for management and auditors |
| **Shared link** | A read-only HTML report for a set period |
| **Re-test** | `scan verify` re-runs the exact check behind one finding after a fix, and closes it only when that check comes back clear. It cannot yet close a `secret-exposed` finding (ADR-029) *(reconciled)* |
| **Demo** | Live CLI scan, the evidence behind one finding, and the PDF |

---

## 5. Handling the report itself

A security report is a map of an organisation's weaknesses, so it is protected like sensitive data:

- Marked **Confidential** on every page, with the recipient's name in the PDF footer
- Stored encrypted, in India, under the same retention rules as evidence
- Shared links expire and are access-controlled; every view is logged
- Our own staff can read it only through the break-glass process

---

## 6. Build plan

The report is built on the API stage, since it reads the same stored findings.

| Step | Deliverable | Rough effort |
|---|---|---|
| 1 | **Report data model** built from stored scan results | 3–4 days |
| 2 | **JSON export** (the source of truth) | 2 days |
| 3 | **Asset inventory** assembled from the four scanners | 3–4 days |
| 4 | **Score and "fix this first" grouping** | 4–5 days |
| 5 | **HTML report** | 1 week |
| 6 | **PDF generation** | 3–4 days |
| 7 | **AI summary layer**, with the fact-check test | 4–5 days |
| 8 | **Tests:** no secrets in any format, every claim traceable, uncertainty sections present, same scan → same report | ongoing with each step |

**Approximate total: 5–7 weeks**, partly in parallel with the dashboard.

**Exit criteria**
- A Light scan of a test domain produces JSON, HTML and PDF reports
- Every statement in the report traces to a finding
- A planted canary secret appears in the report by type only
- Two runs of the same scan produce identical reports

---

## 7. Decisions (12 October 2026)

1. **Score method:** both. An overall score **plus** sub-scores by area. Every score is traceable down to the findings that produced it.
2. **PDF branding:** our brand only. White-label for agencies is a later decision.
3. **Shared links:** optional, offered only where needed. When used, they expire (suggested default: 7 days) and every view is logged.
4. **AI summaries:** **included in Alpha.** Condition: every summary is labelled as AI-written, and a mandatory test checks it against its findings so it can never add, remove or change a fact. Step 7 of the build plan is therefore in Alpha scope.

## 8. Server-module data in the report (PLANNED)

**Every data point in this section is PLANNED: the agent is not built** ([docs/26](26-alpha-build-sequence.md), Steps 2–5). When the agent runs (see the *MVP Alpha Scope* document, Section 5), the report gains:

- A **host inventory** in the asset section: OS and kernel, end-of-life status, reboot needed, key packages.
- A **Server posture** area: patching, SSH and access, services and firewall, CERT-In readiness.
- **Inside-out correlation** in findings: where the agent explains an external finding, both views are shown together with the exact setting to change.
- A **fleet summary** page for multi-server reports: patch compliance, hosts needing a reboot, drift from the fleet baseline, and fleet-wide "fix this first".

---

*Data points reflect the four shipped scanners, reconciled against `docs/21-scanner-catalogue.md` on 12 October 2026. The agent's data points are PLANNED and apply once it is built. The authoritative per-check list, with each check's mode and live status (WORKING or UNDETERMINED), is `docs/21-scanner-catalogue.md`.*
