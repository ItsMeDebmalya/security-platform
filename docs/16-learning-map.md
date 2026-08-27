# 16 — Learning Map

*Everything the developer needs to understand to build this product, assuming little dev experience and minimal security experience. Not a tutorial — a map of what to go and learn, in a sensible order, with a one-line "why it matters here" on each item so you know it is not busywork.*

**How to use this.** Do not try to learn it all first. Learn Tier 0 and Tier 1 before touching code, then pull items from later tiers *as the plan reaches them* — the roadmap tells you when. An item marked ★ is one you will hit in the first month.

Legend: ★ needed immediately · ◐ needed within Phase 1 · ○ needed later, learn when the plan reaches it.

---

## Tier 0 — The ground you stand on

### Python, properly ★
The whole product is Python. You need to be genuinely comfortable, not just able to copy snippets.
- **Types and the type system** — `str`, `int`, `list`, `dict`, `set`, `tuple`, `None`. *Why: every function in this codebase is type-annotated.*
- **Functions, arguments, keyword arguments, defaults, `*args`/`**kwargs`**
- **Classes, methods, `__init__`, `self`, inheritance, `@classmethod`, `@staticmethod`** — *Why: `BaseScanner` and every scanner is a class.*
- **Dataclasses and `@dataclass(frozen=True)`** — *Why: half of `core/` is frozen dataclasses.*
- **Exceptions: `raise`, `try/except/finally`, custom exception classes** — *Why: the difference between a scan error and an inconclusive finding is which exception is raised where.*
- **Modules, packages, `import`, `__init__.py`, `from x import y`** — *Why: the "scanners never import each other" rule is enforced by reading imports.*
- **Comprehensions, generators, `yield`** — *Why: readability; the code uses them throughout.*
- **Context managers (`with`), and writing your own** — *Why: sockets, files, the lab servers all use them.*
- **Decorators** — *Why: `@register` on every scanner is one.*
- **`async`/`await` and the event loop** — ◐ *Why: not used yet, but the Playwright crawler and high-concurrency scanning will need it.*

### The command line and the shell ★
- **bash basics: `cd`, `ls`, pipes `|`, redirection `>`, `grep`, `head`/`tail`, exit codes `$?`**
- **Environment variables, `PATH`, `export`** — *Why: `uv` and the scanners read config from the environment.*
- **SSH, and why key auth beats passwords** — *Why: you deploy and test over it.*

### Git and version control ★
- **commit, branch, merge, the staging area, `git log`, `git diff`**
- **remote, push, pull, fetch, and what a merge conflict actually is** — *Why: you already hit one this project.*
- **reading history as a record** — *Why: the authorisation file's git history IS the audit log; that is a design decision, not a convenience.*

### How a program becomes a running thing ★
- **The Python toolchain: `uv`, virtual environments, `pyproject.toml`, lockfiles** — *Why: `make install` is `uv sync`; reproducibility depends on the lockfile.*
- **Linting and formatting: `ruff`** — *Why: `make lint` gates every commit.*
- **Type checking: `mypy --strict`** — *Why: it catches a class of bug before the code runs.*
- **Testing: `pytest`, what a unit test is, assertions, fixtures** — *Why: this project is test-first; you write the test before the code.*
- **Test-driven development as a discipline** — *Why: it is how every scanner here was built, and why the bugs got caught.*
- **Continuous Integration (CI), GitHub Actions** — ◐ *Why: the gate runs there; note D1 — it has never actually run.*

---

## Tier 1 — How the internet works (you cannot scan what you do not understand)

### The network stack ★
- **IP addresses (v4 and v6), what an octet is, `127.0.0.1` / loopback, `0.0.0.0`** — *Why: every "bound to loopback vs every interface" safety decision rests on this.*
- **Ports, and what "listening on a port" means** — *Why: a scanner connects to ports; 443 is TLS, 1883 is MQTT, and so on.*
- **TCP vs UDP** — *Why: TCP for most scanning, UDP for CoAP/mDNS/SSDP in the IoT tool.*
- **The client-server model, sockets, a handshake** — *Why: every scanner is a client making a connection.*
- **NAT, private vs public IP ranges, firewalls** — *Why: it is why most IoT devices are not externally visible, which shaped the IoT plan.*
- **CIDR notation (`10.0.0.0/24`)** — *Why: the IoT and network scanners take a range, not a single host.*

### DNS ★
- **What DNS is: names to addresses, resolvers, authoritative nameservers, recursion, caching**
- **Record types: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR** — *Why: the email scanner reads all of these; TXT holds SPF/DMARC/DKIM.*
- **Response codes: NOERROR, NXDOMAIN, NODATA, SERVFAIL** — *Why: "SERVFAIL is not the same as no record" is a core accuracy rule in Tool 1.*
- **DNS wildcards** — *Why: a wildcard makes every guessed name look real; it breaks naive subdomain enumeration and the email scanner guards against it.*
- **Reverse DNS, and why it is weak evidence** — ◐

### HTTP ◐
- **Requests, responses, methods (GET/POST/…), status codes, headers, cookies**
- **HTTPS = HTTP over TLS**
- **Redirects, and why following one out of scope is dangerous** — *Why: the HTTP client refuses to.*
- **Security headers: HSTS, CSP, X-Frame-Options, SameSite cookies** — *Why: the web scanner (Tool 4) checks these.*
- **REST and JSON APIs, OpenAPI/Swagger** — ○ *Why: the API scanner.*

---

## Tier 2 — Security fundamentals (the "what are we even looking for")

### The mental model ★
- **The CIA triad: Confidentiality, Integrity, Availability** — *Why: every finding degrades one of these; it is the vocabulary of severity.*
- **Vulnerability vs exploit vs threat vs risk** — *Why: we find vulnerabilities and prove them; we never exploit. That distinction is the whole legal posture.*
- **Attack surface** — *Why: half the product is "external attack surface management".*
- **Defence in depth, least privilege** — *Why: the remediation advice rests on these.*
- **Passive vs active testing** — ★ *Why: it decides whether a check needs authorisation; it is a per-check property in the plan.*
- **Responsible disclosure, authorisation, "scope"** — ★ *Why: scanning without authorisation is a crime, not a bug. This is why `core/authz.py` exists.*

### The catalogues you will refer to constantly ◐
- **OWASP Top 10 (web)** — the canonical list of web vulnerability classes.
- **OWASP API Security Top 10** — *Why: the API scanner is built around it; BOLA/BFLA live here.*
- **CWE (Common Weakness Enumeration)** — *Why: every finding carries a CWE id.*
- **CVE (Common Vulnerabilities and Exposures) and the NVD** — *Why: "this software has known bug CVE-XXXX" is the whole vulnerability-matching feature.*
- **CVSS (scoring) — and why we do NOT just use it** — *Why: we separate severity from confidence; CVSS conflates them.*
- **CPE (Common Platform Enumeration)** — ○ *Why: the identifier that maps "this software version" to a CVE list; its poor IoT coverage is why 5b's gate is lower.*
- **MITRE ATT&CK** — ○ *Why: the vocabulary for the "connect findings into an attack story" work.*
- **KEV (Known Exploited Vulnerabilities catalogue)** — ○ *Why: "is this CVE actually being exploited in the wild" is better prioritisation than CVSS alone.*

### Specific vulnerability classes, learn as the tool reaches them ○
- **Injection: SQL injection, command injection** — control-vs-test proof is the textbook example.
- **SSRF (Server-Side Request Forgery)** — *Why: the flagship out-of-band-callback proof targets this.*
- **XSS (Cross-Site Scripting)**
- **BOLA / IDOR and BFLA (broken object/function-level authorization)** — *Why: the API scanner's differentiator; needs holding two identities at once.*
- **XXE, mass assignment, JWT weaknesses** — for the API scanner.
- **Information disclosure, directory listing** — for the web scanner.
- **Subdomain takeover** — *Why: Tool 3 includes it.*

---

## Tier 3 — Cryptography and certificates (Tool 2's world)

### TLS and certificates ◐
- **What TLS does: encryption, integrity, authentication of the server**
- **The handshake, protocol versions (SSL 3.0 → TLS 1.3), why old ones are dead** — *Why: RFC 8996; the `tls-protocol-obsolete` check.*
- **Cipher suites, forward secrecy (ECDHE)** — *Why: the weak-cipher and no-forward-secrecy checks.*
- **X.509 certificates: subject, issuer, SAN, validity dates, the chain, roots and intermediates** — *Why: half of Tool 2's checks read these fields.*
- **Certificate Authorities, the trust store, path building** — *Why: "untrusted root" vs "self-signed" vs "incomplete chain" are three different findings for three reasons.*
- **Hashing and signatures: SHA-1 vs SHA-256, why SHA-1 is deprecated** — *Why: the weak-signature check.*
- **Key strength: RSA vs elliptic-curve, why 1024-bit RSA is weak** — *Why: the weak-key check.*
- **Certificate Transparency (CT), OCSP/CRL revocation** — ○ *Why: CT is a check; revocation is the gap D12.*

### The 2026 crypto frontier ○
- **The CA/Browser Forum and certificate-lifetime reduction (200→100→47 days)** — *Why: the deprecation clock's headline. Verify against the ballot, per D13.*
- **Post-quantum cryptography: the quantum threat, "harvest now decrypt later", ML-KEM/Kyber, hybrid key exchange (X25519MLKEM768)** — *Why: the post-quantum-exposure differentiator. Needs a newer toolchain (0b.5).*

---

## Tier 4 — The specific protocols each tool speaks

### Email authentication (Tool 1) ◐
- **How email is sent (SMTP), and why the "From" is forgeable** — *Why: the whole reason SPF/DMARC/DKIM exist.*
- **SPF (RFC 7208): the record, mechanisms, the 10-lookup limit** — *Why: the lookup-limit check is the one almost nobody gets right.*
- **DKIM (RFC 6376): signatures, selectors, why selectors cannot be enumerated** — *Why: `dkim-missing` is permanently inconclusive because of this.*
- **DMARC (RFC 7489): policy (none/quarantine/reject), pct, alignment, rua/ruf** — *Why: the `pct=5` false-green that free checkers miss.*
- **MTA-STS, TLS-RPT, the null MX (RFC 7505)** — the Standard-mode checks.

### AI / agent infrastructure (Tool 4's new half) ○
- **What an LLM API endpoint looks like on the network**
- **MCP (Model Context Protocol): what it is, why an exposed MCP server is dangerous, default-bind misconfigurations** — *Why: the AI-exposure differentiator.*
- **Agent architectures at a high level** — enough to know what "the tools an agent can call" means and why we do not read them.

### IoT protocols (Tool 5) ○
- **MQTT: publish/subscribe, brokers, ports 1883 vs 8883, CONNACK codes** — *Why: `CONNACK 0 vs 5` is the auth control-vs-test pair.*
- **CoAP: constrained devices, UDP, DTLS, `/.well-known/core`** — *Why: the CoAP checks.*
- **mDNS/DNS-SD, SSDP/UPnP, the device description XML** — *Why: device discovery and identification.*
- **SNMP, Telnet, and why they are dangerous when exposed**
- **Why devices are fragile** — *Why: the stop-the-line safety rules exist because of this.*

---

## Tier 5 — The concepts specific to THIS product's design

*These are not general knowledge — they are the ideas the plan is built on. Read the doc named beside each.*

### The measurement discipline ★
- **Precision, recall, false positive/negative, true positive/negative** — `docs/10-measurement.md`. *Why: the gate is these numbers; you cannot reason about the product without them.*
- **Why precision beats recall here**
- **The five states: confirmed / highly_likely / suspected / informational / inconclusive** — `docs/01-architecture.md`. *Why: this is the product's honesty, encoded.*
- **Detected vs derived findings** — ADR-018. *Why: a calculated finding inherits its confidence and is measured separately.*
- **A corpus proves regression, not correctness** — ADR-017. *Why: it is why live testing found every real bug.*

### The confidence model ◐
- **Bayesian reasoning at a basic level: prior, likelihood, updating a belief** — *Why: `core/confidence.py` is log-odds Bayesian updating. You do not need the maths deep, but you need the shape.*
- **Log-odds, likelihood ratios** — *Why: how evidence combines.*
- **Independence: why three variants of one technique are one signal** — *Why: `independence_class`; it is what stops fake corroboration.*
- **Calibration (Platt scaling, reliability diagrams, Brier score)** — ○ *Why: Phase 4; why confidence stays "provisional" until then.*

### The architecture ideas ★
- **The Scanner Contract, and why freezing it mattered** — `docs/01-architecture.md`, ADR-002.
- **Why scanners never build their own clients or import each other** — *Why: the safety guarantees depend on it.*
- **Evidence as control-vs-test pairs** — *Why: "the server errored" is not evidence; this is the whole differentiator.*
- **Record/replay, and why corpus tests must be deterministic**
- **The asset graph** — ADR-019. *Why: how one scanner feeds another without importing it.*
- **Prove / connect / close** — ADR-022. *Why: the mitigation differentiator.*
- **The out-of-band callback server** — ADR-004, `docs/01-architecture.md`. *Why: how blind bugs are proven without exploitation.*

---

## Tier 6 — The things that keep you legal and safe

- **Software licences: MIT, Apache-2.0, BSD, ISC vs the GPL family and AGPL** — ADR-003. ★ *Why: embedding GPL code wrong is a legal problem; the licence check gates the build.*
- **"GPL as a data licence"** — *Why: you cannot seed a fingerprint DB from GPL data either.*
- **Authorisation and the law: why scanning without permission is a crime (CFAA-equivalents, India's IT Act)** — ★ *Why: `core/authz.py` is a legal control, not a feature.*
- **Ownership verification: DNS nonce vs attestation** — `docs/09-ownership-verification.md`.
- **Rate limiting, adaptive backoff, and not causing outages** — *Why: being wrong here means abuse complaints and blocked IP ranges.*
- **Secret handling: redaction at capture time, never storing customer secrets** — *Why: a non-negotiable in the guidelines.*
- **The Indian regulatory context: CERT-In directions, the DPDP Act** — ○ *Why: it shapes where evidence can be stored and who the first buyer is. Your analyst owns this; you need enough to follow the conversation.*

---

## Tier 7 — When the platform gets built (Phase 6, far off) ○

Learn these only when the roadmap reaches Phase 6. Listed so you know they exist.
- Web frameworks (FastAPI or similar), REST API design
- Databases: relational (Postgres), SQL, migrations, indexing
- Job queues and workers (why a scan cannot run in a web request)
- Object storage for evidence blobs
- Authentication and authorization for the platform itself (sessions, OAuth, RBAC)
- Multi-tenancy and `org_id` on every row
- Containers and orchestration (Docker you already use; Kubernetes later)
- Sandboxing untrusted work (crawling hostile sites, cloning customer repos)
- Observability: logging, metrics, tracing
- Secrets management (Vault or a cloud KMS)

---

## Suggested first-month path

1. **Python** to the point you can read every file in `core/` without guessing (Tier 0).
2. **Git, uv, pytest, ruff, mypy** — the daily loop (Tier 0).
3. **Networking + DNS + how a socket works** (Tier 1) — enough to understand what a scanner *does*.
4. **The security mental model** (Tier 2, the ★ items) — vulnerability vs exploit, passive vs active, why authorisation is legal not optional.
5. **This product's own ideas** (Tier 5, the ★ items) — the five states, precision/recall, the Scanner Contract, evidence pairs.

At that point you can read the whole codebase, follow every response I give, and start building Tool 3 with your eyes open. Everything else is pulled in as the roadmap reaches it.

---

## A note on how to learn these with AI help

You do not need a course for most of these. The efficient loop, given you are building with AI assistance:

- For a **concept** (e.g. "what is forward secrecy"): ask for it explained simply, then ask "show me where this appears in our codebase." Seeing it in context you already care about beats an abstract tutorial.
- For a **skill** (e.g. Python classes): build something tiny and wrong, then have it critiqued. You learn faster from a broken thing being fixed than from a working example being explained.
- For a **security topic**: always ask "how would an attacker use this, and how do we detect it without exploiting it?" — that framing is the product's whole worldview and keeps the learning anchored to what you are building.
- **Verify claims about the real world** (dates, standards, statistics) against primary sources, not against me and not against a blog — the project has a whole discipline about this (ADR-017, D13). Treat your own learning the same way.
