# Reference — Product Spec (full tool and feature catalogue)

*Preserved verbatim from v2, Parts A and B. This is the catalogue of what each tool does and what each platform feature is — the "what", not the "when" or the "how".*

**Use this document for:** what a given scanner should detect, what a platform feature covers.
**Do not use it for:** build order (see [../03-roadmap.md](../03-roadmap.md)), decisions (see [../02-decisions.md](../02-decisions.md)), or the phase labels below — **the "Phase:" annotations in this document are the original v2 phases and are superseded by [../03-roadmap.md](../03-roadmap.md).**

The scan-mode definitions referenced throughout are in [../00-context.md](../00-context.md).

---

# PART A — SECURITY TOOLS (what users can run)

---

## A1. Website Scanner

**Summary:** Scans a website or web application for security weaknesses.

**Light Scan — what the user gets**
- Server software and version detection
- Missing or weak HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Insecure cookie settings (missing Secure, HttpOnly, SameSite)
- Directory listing enabled
- Information disclosure in error pages and response headers
- Technology stack detection (CMS, framework, JS libraries, web server)
- Outdated component detection based on version
- robots.txt and sitemap exposure review
- Basic SSL/TLS check summary

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Full crawl of the site including JavaScript-rendered pages
- **Hidden file and directory discovery** — admin panels, backups, config files (this is the job that gobuster, dirb, dirbuster and ffuf do; we build it in rather than shipping those tools)
- **Historical URL discovery** — pull old URLs from web archives to find forgotten endpoints that are still live
- SQL injection testing
- Cross-site scripting (XSS) testing — reflected, stored, DOM-based
- Server-side request forgery (SSRF) testing
- Path traversal and local file inclusion testing
- Open redirect testing
- CORS misconfiguration testing
- Authentication and session weaknesses
- Known CVE matching against detected components
- Business logic and error-handling tests
- OWASP Top 10 2025 mapping for every finding

**How it works (mechanism)**
1. We resolve the domain and confirm the site is reachable.
2. A crawler visits pages and collects every URL, form, and parameter.
3. We also pull historical URLs from web archives and check which are still live.
4. For Light: we only read what the server sends back and analyse it.
5. For Standard: we send safe test payloads to each parameter and compare responses against a control request.
6. Each result goes to a validation step that re-tests it before we show it.
7. Findings are scored, deduplicated, and explained by AI.

**Tools and resources needed**
- Nuclei (MIT licence — free for commercial use) for template-based checks
- Our own crawler built on Playwright/Chromium for JavaScript-heavy sites
- Our own injection testing engine — **this must be custom built**, it is where accuracy is won
- Our own content discovery engine (ffuf-style logic plus curated wordlists)
- Web archive APIs for historical URL mining
- A technology fingerprint database (build our own, Wappalyzer-style)
- CVE data from NVD and OSV.dev
- An out-of-band callback server (our own, self-hosted) to prove blind vulnerabilities

**Alternatives that exist and why we do not use them directly**
- **Burp Suite / Acunetix / Invicti** — these do the same job commercially. We cannot embed them (licence). Instead we build our own engine and offer **"import Burp findings"** so users can bring results in.
- **OWASP ZAP** — free and usable (Apache-2.0). We may use its crawler in early versions, then replace it.
- **Nikto** — superseded by Nuclei; very high false positive rate.

**Effort:** High. This is the core product.
**Phase:** 1 (must have at launch)

---

## A2. Network Scanner

**Summary:** Finds open ports, running services, and network-level weaknesses.

**Light Scan — what the user gets**
- Host discovery (is the host alive)
- Connectivity check via ping, TCP, UDP
- Top 100 common ports scanned
- Service name identification per open port
- Risk rating per open port (e.g. "port 3306 MySQL exposed to internet = high risk")
- Simple summary: how many ports should not be open

**Standard Scan — what the user gets**
- Full port range scan (all 65,535 ports)
- Service version detection
- CVE matching against detected service versions
- Banner grabbing and protocol analysis
- Weak or default service configuration checks
- Exposed admin and management interfaces (SSH, RDP, database ports, Redis, Elasticsearch, etc.)
- Network exposure summary with recommendations

**How it works (mechanism)**
1. Confirm the IP is in the user's verified scope.
2. Send TCP SYN packets to target ports and record which respond.
3. For open ports, connect and read the service banner to identify the software.
4. Match the version string to known CVEs.
5. **Important:** version strings often lie because Linux distributions backport security patches. So we mark version-only findings as lower confidence and try a behavioural check where possible.

**Tools and resources needed**
- **naabu** (MIT licence) for port scanning — recommended
- Our own service fingerprinting logic
- Distribution security trackers (Debian, Ubuntu, RHEL) to detect backported patches
- Rate limiting and adaptive backoff so we never overload a target

**Alternatives that exist and why we do not use them directly**
- **Nmap** — the best-known tool, but its licence forbids including it in a commercial product, **including inside a Docker container**. We would have to buy an Nmap OEM licence. naabu does the same job with a clean MIT licence.
- **Nessus / OpenVAS** — Nessus is commercial and cannot be embedded. OpenVAS feed terms are unclear for commercial service use. We do the job ourselves and offer **"import Nessus results."**
- **masscan / RustScan** — viable backups if naabu is not fast enough.

**Effort:** Medium.
**Phase:** 2

---

## A3. SSL / TLS Analyzer

**Summary:** Checks the SSL certificate and encryption settings of a domain.

**Light Scan — what the user gets**
- Certificate valid or invalid
- Expiry date and days remaining
- Issuer and certificate authority
- Domain name match check
- Certificate chain completeness
- Self-signed or untrusted certificate warning

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Supported TLS versions (flag SSLv3, TLS 1.0, TLS 1.1 as insecure)
- Cipher suite list with weak cipher warnings
- Perfect Forward Secrecy support
- HSTS header presence and configuration quality
- Certificate transparency log presence
- Known TLS vulnerabilities (Heartbleed, POODLE, ROBOT, etc.)
- Key strength and signature algorithm review
- Overall TLS grade (A+ to F, like SSL Labs)

**How it works (mechanism)**
1. Open a TLS connection to the host on port 443 (and other TLS ports if found).
2. Read the certificate and full chain.
3. Repeatedly negotiate with different protocol versions and cipher lists to see what the server accepts.
4. Compare against current best-practice baselines.

**Tools and resources needed**
- **testssl.sh** (GPLv2 — safe if we run it as a separate process, not linked into our code)
- Or build our own in Go using the standard TLS library — recommended long term because it is much faster
- Certificate Transparency log APIs
- A maintained list of weak ciphers and known TLS CVEs

**Effort:** Low. This is one of the easiest wins.
**Phase:** 1. Very low false positive rate, so it builds trust fast.

---

## A4. Domain & Subdomain Enumeration

**Summary:** Finds all the domains, subdomains, and DNS records belonging to an organisation.

**Light Scan — what the user gets**
- Subdomains from public sources (certificate transparency logs, passive DNS)
- All DNS record types (A, AAAA, MX, TXT, NS, CNAME, SOA)
- WHOIS / RDAP registration details
- Nameserver information
- DNSSEC enabled or not
- Domain expiry date

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Active subdomain brute-forcing with a large wordlist
- Live check on each subdomain (which ones actually respond)
- Technology detection per subdomain
- **Dangling DNS / subdomain takeover detection** — this is high value
- Zone transfer misconfiguration check (AXFR)
- Wildcard DNS detection
- Related domain discovery (same registrant, same certificate, same IP block)
- **OSINT harvesting** — public employee emails, names, and hosts associated with the domain
- Shadow IT discovery — assets the user did not know existed

**How it works (mechanism)**
1. Pull subdomain names from certificate transparency logs (every HTTPS certificate ever issued is public).
2. Query passive DNS databases for historical records.
3. Optionally brute-force common subdomain names.
4. Resolve each candidate and check which are live.
5. For takeover detection: check if a CNAME points to a cloud service (S3, Azure, Heroku, GitHub Pages) that is no longer claimed. If yes, an attacker can claim it.
6. For OSINT: search public sources for email addresses and hostnames tied to the domain.

**Tools and resources needed**
- **subfinder** (MIT) — passive enumeration
- **dnsx** (MIT) — DNS resolution and brute-force
- **httpx** (MIT) — live host probing
- **Amass** (Apache 2.0) — deep enumeration, slower, use for Standard only
- **theHarvester-style OSINT logic** (the tool itself is open source; we can use it or replicate the approach)
- Certificate Transparency APIs (crt.sh and similar)
- Passive DNS provider (paid API — Censys, SecurityTrails, or similar)
- A maintained fingerprint list for takeover detection

**Effort:** Low to medium.
**Phase:** 1 for Light, 2 for Standard.

**Note:** Subdomain takeover detection alone is worth building early. It is easy to detect reliably, it is genuinely dangerous, and it makes users say "I did not know that was there."

---

## A5. Deface Monitoring (Website Change Monitoring)

**Summary:** Watches a website and alerts the user if the content changes unexpectedly — which usually means it was hacked or defaced.

**Light Scan — what the user gets**
- Baseline snapshot of the homepage (HTML hash + screenshot)
- Simple change detection: has the page changed since last check
- Title and meta tag change alerts

**Standard Scan — what the user gets**
- Monitoring of multiple pages, not just the homepage
- Visual screenshot comparison with a difference highlight
- Detection of injected content: hidden links, iframes, crypto miners, redirect scripts
- Detection of suspicious keywords commonly used in defacements
- Malware and blacklist status check (Google Safe Browsing, VirusTotal)
- New third-party script detection (supply chain risk on the page)
- Alert routing to email, Slack, webhook
- Configurable check frequency (hourly to daily)

**How it works (mechanism)**
1. Take a baseline: fetch the page, store the HTML, store a screenshot, store a hash of the important content.
2. On each check, fetch again and compare.
3. Ignore known-changing parts (timestamps, ads, session tokens) so we do not spam false alerts — this filtering is the hard part.
4. If a real change is found, classify it: normal update vs suspicious.
5. Alert with a before/after view.

**Tools and resources needed**
- Playwright/Chromium for screenshots and rendering
- A diffing library for HTML and image comparison
- Google Safe Browsing API (free tier available)
- VirusTotal API (free tier limited, paid for volume)
- A job scheduler for recurring checks
- Storage for baselines and screenshots

**Effort:** Low to medium.
**Phase:** 2

**Note:** This is a monitoring feature, not a scan feature. It drives subscription revenue because it only makes sense as an ongoing service. Good for retention.

---

## A6. API Scanner

**Summary:** Tests REST, GraphQL, and SOAP APIs for security problems.

**Light Scan — what the user gets**
- API endpoint discovery from public sources (JS files, sitemaps, common paths)
- OpenAPI/Swagger specification detection and parsing
- GraphQL introspection check (is introspection publicly enabled — it usually should not be)
- Missing authentication on endpoints
- Security header check on API responses
- HTTP method testing (is PUT/DELETE allowed where it should not be)
- Rate limiting presence check

**Standard Scan — what the user gets**
- Everything in Light, plus:
- **Broken Object Level Authorisation (BOLA/IDOR)** — can user A read user B's data by changing an ID
- **Broken Function Level Authorisation (BFLA)** — can a normal user call an admin endpoint
- Injection testing on all API parameters (SQL, NoSQL, command)
- Mass assignment testing
- Excessive data exposure (does the API return more fields than the UI shows)
- JWT token weaknesses (weak signing, none algorithm, no expiry)
- API key exposure in responses or client code
- GraphQL query depth and complexity abuse
- Spec drift detection (endpoints running that are not in the documentation)
- OWASP API Security Top 10 mapping

**How it works (mechanism)**
1. Import the API spec if the user provides one, otherwise discover endpoints by crawling and analysing JavaScript.
2. Build a map of every endpoint, method, and parameter.
3. For authorisation testing we need **two test accounts**. We log in as User A, create or find an object, then try to access it as User B. If it works, that is a confirmed BOLA.
4. For injection, we send safe payloads and compare responses against a control request.

**Tools and resources needed**
- Our own API testing engine — **this must be custom built**
- OpenAPI/Swagger parser libraries
- GraphQL introspection client
- JWT analysis library
- A session manager that can hold multiple identities at once

**Effort:** High, but very high value.
**Phase:** 2

**Note:** This is our biggest differentiation opportunity in Part A. Most competitors do "API scanning" that is really just web scanning pointed at an API URL. Real authorisation testing needs multiple identities and almost nobody does it properly. If we do this well, it is a reason to choose us.

---

## A7. Email Security Scanner

**Summary:** Checks whether a domain's email is configured to prevent spoofing and phishing.

**Light Scan — what the user gets**
- SPF record present and valid
- DKIM record detection
- DMARC record present, and what policy (none / quarantine / reject)
- MX record listing and mail provider identification
- Simple spoofing risk verdict: can someone send email pretending to be this domain

**Standard Scan — what the user gets**
- Everything in Light, plus:
- SPF syntax analysis, DNS lookup count (limit is 10, exceeding it breaks SPF)
- SPF too-permissive check (`+all` or `?all` is dangerous)
- DKIM key strength check
- DMARC alignment mode analysis (strict vs relaxed)
- DMARC reporting addresses configured or not
- BIMI record check
- MTA-STS and TLS-RPT policy check
- Open relay test on mail servers
- Mail server TLS configuration
- Domain reputation and blacklist status
- Look-alike domain detection (typosquatting domains that could be used to impersonate)

**How it works (mechanism)**
1. Query DNS for TXT records at specific names (`_dmarc.domain.com`, `selector._domainkey.domain.com`).
2. Parse each record against the RFC rules.
3. Simulate what a receiving mail server would decide when it gets a spoofed email.
4. For look-alike domains, generate common typo variations and check which are registered.

**Tools and resources needed**
- Standard DNS libraries — no special tool needed
- SPF/DKIM/DMARC parsing logic (well-documented RFCs, straightforward to build)
- Blacklist APIs (Spamhaus and similar)
- A typosquatting permutation generator

**Effort:** Low. One of the cheapest tools to build.
**Phase:** 1

**Note:** Very high value per unit of effort. Almost entirely passive, legally safe, deterministic (near zero false positives), and most companies have a broken DMARC record. Great free-tier tool.

---

## A8. Container Scanner

**Summary:** Scans Docker images and Kubernetes configurations for vulnerabilities.

**Light Scan — what the user gets**
- Image metadata and base image identification
- Base image age and whether it is outdated
- Known CVEs in OS packages
- Exposed ports declared in the image
- Whether the container runs as root
- Basic Dockerfile best-practice checks

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Full CVE scan across OS packages and application dependencies
- Secrets embedded in image layers (API keys, passwords, private keys)
- Misconfiguration checks against CIS Docker Benchmark
- Kubernetes manifest analysis (privileged containers, host network, missing resource limits)
- Kubernetes RBAC over-permission analysis
- Image signature and provenance verification
- Layer-by-layer breakdown showing which layer introduced each problem
- SBOM (Software Bill of Materials) generation

**How it works (mechanism)**
1. User connects a registry (Docker Hub, ECR, GCR, ACR) or uploads an image.
2. We pull the image and unpack its layers.
3. We list every installed package and its version.
4. We match those against vulnerability databases.
5. For secrets, we scan file contents in each layer with pattern matching.

**Tools and resources needed**
- **Trivy** (Apache 2.0) — excellent and free for commercial use
- **Syft** (Apache 2.0) — SBOM generation
- **Grype** (Apache 2.0) — vulnerability matching
- **Checkov** or **KICS** (Apache 2.0) — Kubernetes and IaC misconfiguration
- Registry authentication handling
- Storage and compute for unpacking large images

**Effort:** Medium. The open-source tools do most of the work.
**Phase:** 4

**Warning:** These tools produce very high volumes of findings. A single base image can produce 500+ CVEs, most of which are not exploitable. **We must add reachability filtering** (is the vulnerable package actually used by the application) or this tool will be noise and users will ignore it.

---

## A9. Supply Chain Scanner

**Summary:** Checks the third-party code and services a project depends on.

**Light Scan — what the user gets**
- Dependency list from manifest files (package.json, requirements.txt, pom.xml, go.mod, etc.)
- Known CVEs in direct dependencies
- Outdated package detection
- Licence listing

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Transitive (indirect) dependency analysis — the full tree
- **Reachability analysis** — is the vulnerable function actually called by the code
- Typosquatting and dependency confusion detection
- Abandoned or unmaintained package detection (no updates, no maintainer)
- Suspicious package behaviour (install scripts, obfuscated code, network calls at install time)
- Package integrity and signature verification
- Build pipeline and CI/CD configuration security
- Third-party script analysis on the live website (what external JS is loaded)
- Licence compliance and conflict detection
- Full SBOM export in CycloneDX or SPDX format

**How it works (mechanism)**
1. Read the project's dependency manifests and lockfiles.
2. Build the full dependency tree including indirect dependencies.
3. Match every package and version to vulnerability databases.
4. For reachability: analyse the code to see whether the vulnerable function is actually imported and called. If not, downgrade the severity — this removes most of the noise.
5. For typosquatting: compare package names against popular package names for suspicious similarity.

**Tools and resources needed**
- **Syft + Grype** (Apache 2.0)
- **Trivy** (Apache 2.0)
- OSV.dev API (free, Google-maintained, excellent coverage)
- GitHub Security Advisory database (free)
- Our own reachability analysis engine — this is the differentiator
- Package registry APIs (npm, PyPI, Maven, etc.)

**Effort:** Medium for basic, High for reachability.
**Phase:** 3

**Note:** OWASP moved Software Supply Chain Failures up to number 3 in the 2025 Top 10 and specifically noted that testing in this area lags behind. That means the tooling market is behind, which is an opening for us.

---

## A10. Cloud Security Posture Management (CSPM)

**Summary:** Connects to a user's cloud account and checks for misconfigurations.

**Light Scan — what the user gets**
- Read-only connection to the cloud account
- Inventory of resources (compute, storage, databases, network)
- Publicly exposed storage buckets
- Publicly accessible databases
- Security groups open to the internet (0.0.0.0/0)
- Unencrypted storage volumes
- Root account MFA status

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Full CIS Benchmark assessment for AWS / Azure / GCP
- IAM analysis: over-privileged users, unused credentials, old access keys
- Privilege escalation path detection
- Logging and monitoring gaps (CloudTrail, flow logs, audit logs disabled)
- Encryption at rest and in transit gaps
- Network architecture review (public subnets, missing segmentation)
- Compliance mapping (PCI DSS, SOC 2, ISO 27001, HIPAA)
- Multi-account and multi-cloud view
- **Link between cloud resources and our external scan results** — this is our unique angle

**How it works (mechanism)**
1. User creates a read-only role in their cloud account and gives us the role ARN (AWS) or equivalent.
2. We assume that role and call the cloud provider's APIs to list configuration.
3. We check each resource's configuration against a rule set.
4. **We do not scan the running workloads** — we read configuration only. This is safe and requires no agent.

**Tools and resources needed**
- **Prowler** (Apache 2.0) — best open-source starting point, strong CIS Benchmark coverage
- **ScoutSuite** (GPL) — alternative, run as a separate process
- Cloud provider SDKs (boto3 for AWS, etc.)
- Secure credential and role handling (this is a serious security responsibility — we hold access to customer clouds)

**Effort:** Medium to start with AWS, then Azure and GCP.
**Phase:** 4

**Important:** Do not try to compete with Wiz on cloud breadth. Our angle should be narrow and specific: **connect what we see from the outside to what we see inside the cloud.** For example: "This exposed subdomain points to this EC2 instance, which has this IAM role, which can read this S3 bucket containing customer data." Nobody at our price point does that link.

---

## A11. Code Scanner (SAST + Secrets)

**Summary:** Analyses source code for security bugs and hardcoded secrets.

**Light Scan — what the user gets**
- Repository connection and language detection
- Hardcoded secret detection (API keys, passwords, tokens, private keys)
- Basic insecure pattern detection (eval, exec, weak crypto, disabled certificate checks)
- Dependency manifest scan

**Standard Scan — what the user gets**
- Everything in Light, plus:
- Full static analysis with data flow tracking (does user input reach a dangerous function)
- Injection vulnerability detection in code (SQL, command, LDAP, XPath)
- Authentication and authorisation logic flaws
- Insecure cryptography usage
- Hardcoded credentials across full git history, not just current code
- **Live secret validation** — we actually test whether a found API key still works
- Infrastructure-as-Code scanning (Terraform, CloudFormation, Kubernetes YAML)
- Pull request integration with inline comments
- CI/CD pipeline integration

**How it works (mechanism)**
1. User connects GitHub / GitLab / Bitbucket via OAuth, or uploads a zip.
2. We clone the repository into an isolated sandbox.
3. We parse the code into an abstract syntax tree.
4. We run rules that trace how data flows from user input (source) to a dangerous operation (sink).
5. For secrets, we use pattern matching plus entropy analysis, then optionally validate the credential against the real service.

**Tools and resources needed**
- **Opengrep** (LGPL-2.1) — use this, **not Semgrep**
- **Important licence note:** Semgrep changed its rule licence in December 2024. Semgrep's own maintained rules are now only allowed for internal, non-competing, non-SaaS use. We cannot use them in our product. Opengrep is the community fork that kept everything open, and we should write our own rules on top of it.
- **Gitleaks** (MIT) for secret detection
- **TruffleHog** does secret validation but is AGPL-3.0, which is a problem for SaaS — legal check needed, or build our own validator
- Git history analysis tooling
- Isolated sandbox for cloning untrusted code
- Our own rule corpus — this becomes valuable IP over time

**Effort:** High.
**Phase:** 4

**Note on live secret validation:** "We found something that looks like an AWS key" is low value. "We found an AWS key and confirmed it is still active" is extremely high value. This is a small feature with a big impact and few competitors do it.

---

## A12. AI / LLM Application Scanner

**Summary:** Tests AI-powered applications, chatbots, and agents for security issues.

**Light Scan — what the user gets**
- Detect that an LLM is in use and identify the provider
- Exposed AI API keys in frontend code
- Rate limiting present or not
- System prompt visible in client-side code

**Standard Scan — what the user gets**
- Prompt injection testing — direct and indirect
- System prompt leakage
- Sensitive data extraction from the model
- Excessive agency — can the AI take actions it should not
- Insecure output handling — does AI output reach a database, shell, or browser unfiltered
- Unbounded consumption / cost abuse
- RAG data leakage across users
- Vector database and embedding weaknesses
- Full OWASP Top 10 for LLM Applications (2025) mapping

**How it works (mechanism)**
1. We send a library of adversarial prompts to the application.
2. We measure how often the model behaves unsafely.
3. Results are reported as a **success rate over N attempts**, not a yes or no — because these attacks are probabilistic, not deterministic. Reporting them honestly as a rate is itself a differentiator.

**Tools and resources needed**
- **garak** (Apache 2.0) — LLM vulnerability probing
- **PyRIT** (MIT) — adversarial testing framework
- Our own prompt corpus, maintained and versioned
- OWASP LLM Top 10 (2025) as the taxonomy

**Effort:** Medium.
**Phase:** 4, or pull to Phase 3 if we see market demand.

**Note:** Almost no mainstream scanner covers this yet. Every company is deploying AI features right now. This is a timing window that will close in roughly 18 months.

---

## A13. Mobile App Scanner

**Summary:** Analyses Android APK and iOS IPA files.

**Light Scan — what the user gets**
- App metadata and permissions requested
- Exported components
- Debuggable flag enabled
- Hardcoded strings review

**Standard Scan — what the user gets**
- Hardcoded secrets and API keys
- Insecure local data storage
- Weak cryptography usage
- Certificate pinning present or missing
- Insecure network configuration
- Third-party SDK inventory
- **Backend API testing** — scanning the APIs the app talks to (this is the valuable half)

**Tools and resources needed**
- **MobSF** (open source) for static analysis
- apktool for unpacking
- Our own API testing engine for the backend half

**Effort:** High.
**Phase:** 5

---

## A14. Dark Web / Credential Exposure Monitor

**Summary:** Alerts if employee credentials or company data appear in known breaches.

**What the user gets**
- Breached credentials found for verified company domains
- Which breach, when, and what data type
- Alerts when new exposures appear
- Password reuse risk indication

**How it works (mechanism)**
- We query licensed breach-data providers for domains the user has verified they own.
- We never scrape criminal marketplaces or purchase stolen data.

**Tools and resources needed**
- A commercial licensed provider (e.g. Have I Been Pwned commercial API)
- **Legal review required before building.** Handling breached credentials touches data protection law in most countries.

**Effort:** Low (mostly API integration).
**Phase:** 3, Business tier and above.

---

## A15. Third-Party / Vendor Risk Scanner

**Summary:** Runs our Light Scan against a user's suppliers and produces a risk rating for each.

**What the user gets**
- Security rating per vendor
- Public-facing issues found on each vendor
- Comparison view across all vendors
- Exportable vendor risk report

**Why it matters:** Companies are constantly asked to assess their suppliers. This reuses tooling we already built and creates a new use case with no extra engineering.

**Note:** Passive scanning only, since the user does not own these domains. This is legally important.

**Effort:** Very low (reuses existing scanners).
**Phase:** 3

---

## A16. Compliance Readiness Scanner

**Summary:** Maps all findings to a chosen framework and shows what is missing.

**What the user gets**
- Framework selection: SOC 2, ISO 27001:2022, PCI DSS 4.0.1, GDPR Article 32, HIPAA, NIST CSF 2.0
- Control-by-control status based on our findings
- Gap list with what to fix
- Evidence pack the user can hand to an auditor

**Important wording:** We must call it "compliance **readiness**," never "compliance." We provide evidence; an auditor decides compliance. This distinction matters legally.

**Effort:** Medium.
**Phase:** 3

---

## A17. Attack Surface Monitor

**Summary:** Continuously watches everything we discovered and alerts on changes.

**What the user gets**
- New subdomain appeared
- New port opened
- Certificate expiring
- Technology version changed
- DNS record changed
- New critical CVE affects your stack
- Security score changed

**Why it matters:** This is the feature that converts one-time scanners into monthly subscribers. Commercially it is the single most important item in this list.

**Effort:** Medium.
**Phase:** 2

---

## A18. Security Score & Reporting

**Summary:** A single score plus sub-scores per area.

**What the user gets**
- Overall score 0-100
- Sub-scores: Attack Surface, Application, API, Cloud, Configuration, Email, Compliance Readiness
- Score history over time
- What caused each change

**Rule:** Every score must be clickable down to the exact findings that caused it. An unexplainable score destroys trust with technical users.

**Effort:** Medium.
**Phase:** 2

---

# PART B — PLATFORM FEATURES

These are not scan tools. They are the features around the tools that make the product usable.

## B1. Account and onboarding
- Sign up with email, Google, or GitHub
- Run a Light Scan on any domain **without signing up** (major conversion driver)
- Asset ownership verification: DNS TXT record, file upload, HTML meta tag, or email
- Add assets one at a time, bulk CSV import, or auto-discover from one seed domain
- Set asset criticality (high/medium/low) and environment (production/staging/development)
- Group assets into projects or applications

## B2. Scan management
- Run any scan on demand
- Schedule recurring scans (daily, weekly, monthly)
- Live progress view showing which phase the scan is in
- Pause and stop any scan instantly
- Scan history with full results retained
- Compare any two scans side by side
- Re-scan a single finding without running the whole scan

## B3. Findings management
- One prioritised list across all tools and all assets
- Filter by severity, confidence, status, asset, tool, framework, age
- Group duplicate findings by root cause (one finding, many locations)
- Mark as false positive with a reason
- Accept risk with an expiry date and approver name
- Assign an owner
- Comment thread per finding
- Full status history for audit
- Search across everything

## B4. Request Replay / Manual Tester (new in v2)
- Take any request our scanner made, edit it, and re-send it
- See the full response, headers, timing, and status
- Save and name useful requests
- Compare two responses side by side
- Export as a curl command

**What this is:** This is "curl or Burp Repeater built into our UI."

**Why add it:**
- Power users and pentesters expect it and will otherwise leave our tool to use Burp
- It lets a user verify our findings themselves, which builds trust
- It is cheap to build once the scanning engine exists

**Safety rule:** Only works against assets the user has verified they own, with the same rate limits and payload restrictions as a normal scan.

**Effort:** Low. **Phase:** 2

## B5. Canary Token Generator (new in v2)
- Generate unique tracking tokens (URL, DNS name, email address, document, API key)
- Place them in code, config files, or documents
- Get an alert the moment one is accessed

**Why add it:**
- We already need this infrastructure internally to prove blind vulnerabilities safely
- Exposing it as a user feature costs almost nothing extra
- It is a genuinely useful early-warning tripwire for detecting a breach

**Effort:** Low (we build the server anyway). **Phase:** 2

## B6. Payload Library (internal, partially user-visible)
- Curated test payloads organised by vulnerability class
- Versioned and maintained as internal IP
- Users can see which payload proved a finding (part of showing evidence)
- Advanced users can submit custom payloads for their own scans (Business tier)

**Why it matters:** The quality of our payload library directly determines how many real bugs we find. It should be treated as a maintained product asset, not a config file.

**Effort:** Ongoing. **Phase:** 1 onwards

## B7. AI assistant
- Explain any finding in plain language
- "Explain this to a developer" / "to my manager" / "to an auditor"
- Ask questions about findings and get answers based on our actual evidence
- "What should I fix first and why"
- "Why did my score change since last month"
- Summarise a whole scan in five points
- Suggest what to test next

## B8. Reporting
- Executive summary PDF
- Full technical report
- Developer-focused report with fix instructions
- Compliance evidence pack
- Change report ("what is different since last scan")
- White-label branding for agencies and MSSPs
- Scheduled email delivery
- Export to CSV, JSON, SARIF

## B9. Alerts and integrations
- Email, Slack, Microsoft Teams, webhook, PagerDuty
- Jira, Linear, GitHub Issues, ServiceNow — create tickets automatically
- GitHub, GitLab, Bitbucket — repository connection
- CI/CD: GitHub Actions, GitLab CI, Jenkins
- Cloud connectors: AWS, Azure, GCP
- SIEM export: Splunk, Sentinel, Elastic
- Full REST API with documentation
- CLI tool
- **Import findings from other scanners** (Burp, Nessus, Qualys, ZAP, Snyk) so we can deduplicate and correlate them

**Note on the import feature:** This is strategically valuable. It lets a customer keep their existing tools while making us the place where everything comes together. Over time we become the system of record, and the other tools become replaceable.

## B10. Learning & guidance (tips)
- Short explanation of each vulnerability class in plain language
- "How attackers use this" for each finding type
- Secure coding examples per language
- Links to authoritative references (OWASP, CWE, vendor advisories)
- Optional guided walkthrough for first-time users

**Why add it:** Free-tier users are often students and junior developers. Teaching them builds loyalty and drives word of mouth. It also costs almost nothing since the content is written once.

**Effort:** Low. **Phase:** 2

## B11. Team and access control
- Multiple users per organisation
- Roles: Owner, Admin, Engineer, Auditor, Viewer
- Per-project permissions
- SSO (SAML / OIDC) for enterprise
- Full audit log of who did what
- Data retention settings
- Data residency choice (for enterprise)

## B12. Billing and usage
- Free, Pro, Business, Enterprise tiers
- Daily credit system (credits refresh every day, do not accumulate)
- Usage dashboard showing credits used and remaining
- Credit top-up packs
- Warning at 80% usage, hard stop rather than surprise billing
- Invoice history

