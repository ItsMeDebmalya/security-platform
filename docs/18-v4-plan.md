# Integrated Security Platform — Project Plan


# PART A — THE FOUNDATION

## A1. The two modes

**The idea:** the platform can test in two different ways, and the user chooses which.

| | Defensive | Offensive |
|---|---|---|
| Question it answers | "What weaknesses do I have?" | "What can an attacker actually do?" |
| How it behaves | Looks, reads, checks | Tries things, proves them |
| Safe on production? | Yes | Only with permission and limits |
| When it runs | Continuously | On demand |
| Who pays | Free tier upward | Paid tiers only |

**Example — the house analogy.**
Defensive is walking around a house checking: are the locks good quality, are the windows the right type, is the alarm switched on? You never touch anything.
Offensive is actually trying each door and window to see which one opens, with the owner's written permission.

**Why both:** defensive alone gives a long list of "maybe" problems. Offensive alone is heavy and needs permission, so you cannot run it hourly. Together, defensive watches cheaply and constantly, offensive proves what actually matters.

## A2. One shared core (the most important architecture point)

**The idea:** both modes run on the *same* underlying engine. We build one engine with two front doors, not two products.

**What the shared core contains:** asset discovery, evidence store, validation engine, confidence scoring, attack-path graph, AI analyst, reporting, safety and authorisation.

**Example.** The defensive scan says "this login page has no MFA" (a suspicion). The offensive engine takes that same finding and proves it by actually logging in. Both write to the same findings list — the customer sees **one** issue that got upgraded from "suspected" to "confirmed", not two separate items.


## A3. Two axes — mode and vantage point

**The idea:** "how hard we test" and "where we test from" are separate dimensions.

- **Mode** = defensive or offensive (how thoroughly).
- **Vantage point** = where we stand when testing.

**The three vantage points:**

| Vantage point | Where we are | Example of what we see |
|---|---|---|
| **Unauthenticated** | Outside, not logged in | "Port 3306 is open to the internet" |
| **Authenticated** | Logged in as a user | "Once logged in, user A can open user B's invoice" |
| **Agent** | Inside the server | "The installed OpenSSL is actually patched, despite the version string" |

**Example of why this matters.** From outside, we can only guess what software version is running. With the agent inside, we read the real package database. Same question, completely different accuracy.

## A4. Scan depths

| Depth | Time | Permission needed | Purpose |
|---|---|---|---|
| **Light** | 30 sec - 2 min | None | Free hook — a real result before signup |
| **Standard** | 5 - 30 min | Ownership verified | The paid core |
| **Deep / Validated** | Longer | Ownership + signed authorisation | We *prove* each finding with evidence |

**Example.** Light scan tells you "your SSL certificate expires in 12 days." Deep scan tells you "user A can read user B's records — here is the exact request and the response containing another person's data."

## A5. The four safety classes (new in v4 — know this one well)

**The idea:** every single check declares how risky it is. The engine can never run a check riskier than what the customer authorised.

| Class | What it does | Example |
|---|---|---|
| **Passive** | Only reads public information | Looking up DNS records |
| **Safe-active** | Sends harmless requests, changes nothing | Requesting a page and reading the response headers |
| **Proof-active** | Retrieves the minimum evidence to prove a flaw, then stops | Fetching **one** other user's record to prove access control is broken, then stopping |
| **State-affecting** | May create or change data as an unavoidable result of the test | Race-condition testing (explained in C7) |

**Why the fourth class exists.** This is new in v4 and it is an honesty point. Some tests genuinely cannot avoid changing data. Rather than hide that inside a blanket "we are read-only" claim, we made it a separate tier with its own approval.

**The line to remember:** *"We prove the door is unlocked. We never walk in and rearrange the furniture."* The one exception is race testing, which is declared openly.

## A6. The pre-scan gate

Before any active or offensive scan runs, eight things must happen in order:

1. Ownership confirmed
2. Scope accepted (which assets, how hard, what hours)
3. **Our scanner IPs allow-listed + reachability check passed** *(new)*
4. Role-scoped test accounts provided
5. Authorisation agreement signed
6. Intensity chosen (Safe / Standard / Deep)
7. **Separate opt-in if any state-affecting test is included** *(new)*
8. Blast-radius limits and kill switch confirmed

**Example of why step 3 matters.** Without it: we scan, their firewall silently drops all our traffic, we find nothing, and we report "no issues found." The customer thinks they are secure. They are not — we simply never reached them.

---

# PART B — THE ENGINE

## B1. The automated flow engine

**The idea:** instead of running every check blindly, the engine runs a check, looks at the result, and decides what to test next — like a methodical human tester.

**Worked example:**

```
Start
 |
 +-- Check 1: Find login pages
 |      Found: /admin
 |        |
 |        +-- Check 2: Is MFA required?
 |        |     No MFA  ->  note it, continue
 |        |
 |        +-- Check 3: Try default credentials (safely)
 |              Works  ->  ACCESS GAINED
 |                |
 |                +-- Check 4: Now inside, find APIs
 |                |     Found: /api/records/{id}
 |                |       |
 |                |       +-- Check 5: Test access control
 |                |             Changing {id} returns
 |                |             another user's data
 |                |             ->  CONFIRMED
 |                |
 |                +-- Check 6: Chain them
 |                      weak login + no MFA + broken access
 |                      =  CRITICAL path, with proof
 |
End: report the proven chain
```

**The key insight to explain:** Check 4 and 5 **only became possible** because Check 3 succeeded. A dumb scanner runs all checks in a fixed order and never discovers the chain. This is what makes it behave like an attacker.

## B2. "AI proposes, code confirms"

**The idea:** AI never makes a decision or takes an action. It only suggests.

- **AI advises** what might be worth testing next.
- **The engine decides** — and the engine is ordinary deterministic code, not AI.
- **A deterministic validator proves** the finding before it is reported.

**Why this matters.** AI can hallucinate and gives different answers to the same question. That is unacceptable in a security tool. By keeping AI advisory only, a wrong AI suggestion can never cause a wrong action or a false finding — the validator catches it.

## B3. Playbooks and standards

**Playbook** = a pre-built checklist for a type of assessment (Web App, API, Authentication, Concurrency, IoT, and so on).

**We do not invent the checklist.** We base it on published standards:

| Standard | What it gives us |
|---|---|
| OWASP Top 10 | The main web weakness categories |
| OWASP API Top 10 | API-specific issues |
| OWASP Testing Guide (WSTG) | The step-by-step master methodology |
| OWASP LLM Top 10 | AI and chatbot issues |
| OWASP IoT Top 10 / FSTM | IoT and firmware |
| MITRE ATT&CK | Real attacker techniques, for the narrative |
| PTES | Overall pentest structure |
| CIS Benchmarks | OS and service hardening baselines |

**Why this is a selling point.** "We tested against the OWASP Testing Guide and mapped results to MITRE ATT&CK" is verifiable. A competitor saying "we run 50 checks" tells the buyer nothing about what is *missing*.

---

# PART C — THE TEST CLASSES (with examples)

## C1. Authentication vs Authorization — the distinction that drives v3 and v4

| | Authentication | Authorization |
|---|---|---|
| Question | "Are you who you say you are?" | "Now you are in, what can you touch?" |
| Concerns | Passwords, MFA, login, sessions | Permissions, roles, ownership of records |
| Tool coverage | Every scanner does this | Almost none do this properly |

**Example.** Your office ID card gets you through the front door — that is authentication. Whether that card opens the finance room is authorization. Most tools only check the front door.

**Why authorization is harder to automate.** To test it you need to be logged in as *two different users at once* and check whether one can reach the other's data. A single-session scanner structurally cannot do this.

## C2. The permission matrix

**The idea:** build a grid of roles against resources. Every cell that *should be denied* becomes a test.

```
            Resource A    Resource B    Admin Action
Admin          allow         allow          allow
Manager        allow         allow        must deny
User A         allow       must deny      must deny
User B       must deny       allow        must deny
Anonymous    must deny     must deny      must deny
```

Any "must deny" cell that returns data is a confirmed flaw.

**Why this is our strongest selling point:** a customer cannot easily produce this themselves, and it is directly usable as audit evidence for access-control requirements.

## C3. The authorization test classes, one example each

| Class | Plain-language example |
|---|---|
| **Object-level access (BOLA)** | Invoice URL ends `/invoice/1001`. Change it to `/invoice/1002` and you see another customer's invoice. |
| **Function-level access (BFLA)** | A normal user calls `/api/admin/delete-user` and it works, even though the button is hidden in their UI. |
| **Vertical escalation** | A normal user becomes an administrator. |
| **Horizontal escalation** | User A reaches User B's data — same privilege level, different person. |
| **Forced browsing** | The "Admin Panel" menu item is hidden for normal users, but typing `/admin` directly still opens it. Hiding is not securing. |
| **Mass assignment** | The signup form sends `name` and `email`. You add `"role": "admin"` to the request body and the system accepts it. |
| **Anonymous access** | An endpoint works with no login at all. |

## C4. Race conditions / TOCTOU (new in v4 — explain this well)

**TOCTOU** = "Time Of Check To Time Of Use" — the tiny gap between a system *checking* something and *acting* on it.

**The clearest example — a gift voucher.**
You have one voucher worth Rs 500, valid for a single use.
- Normal behaviour: you redeem it, the system marks it used, a second attempt fails.
- The attack: you send 20 redemption requests *in the same instant*. All 20 reach the "is this voucher unused?" check **before any of them marks it used**. All 20 pass. You receive Rs 10,000 from a Rs 500 voucher.

**Other forms of the same bug:**

| Type | Example |
|---|---|
| Double-spend | Money debited once, credited twice |
| Limit bypass | "One per customer" offer claimed five times |
| Duplicate provisioning | Two accounts or tickets created from one entitlement |
| Approval bypass | A workflow jumps two steps, skipping an approval gate |
| Rate-limit bypass | Throttling defeated by sending in parallel instead of in sequence |

**Why every normal scanner misses this.** A conventional scanner sends one request, sees the limit enforced, and reports the control as working. The bug only appears under simultaneous requests.

**The honest catch — and how we handle it.**
Proving a double-redemption *creates* a second redemption. So this test **cannot be read-only.** We handle it openly:
- Classified **State-affecting** — the highest approval tier
- Separate per-scan opt-in, on top of normal authorisation
- Test accounts only, never real customer accounts
- Bounded: limited parallel requests, limited attempts, one operation at a time
- A **cleanup report** listing every record created, so the customer can reverse it
- Staging preferred; production requires a named approver


## C5. Concurrent sessions (new in v4)

**The idea:** what happens when one account is logged in from several places at once?

| Test | What we check |
|---|---|
| Multi-location login | Can one account have 5 active sessions? Is that intended? |
| Logout propagation | Logging out on one device — do the others die? |
| **Invalidation on password change** | **The critical one** — see below |
| Invalidation on role change | If permissions are reduced, does the existing session keep the old rights? |
| Session limit | If a maximum is configured, is it enforced? |
| Timeouts | Do idle and absolute timeouts apply to all sessions equally? |

**The critical example.** Someone steals your session token. You notice something is wrong and change your password to lock them out. **If the application does not terminate existing sessions on password change, the attacker is still logged in.** You believe you have revoked their access. You have not.

**Cost note to mention:** this class is read-only and reuses the multi-identity session manager we already need for authorization testing.

---

# PART D — FIREWALL (Section 5 of the plan)

## D1. The core problem — false negatives

**What goes wrong without this.** We send a test. The WAF blocks it. We record "not vulnerable." **That is wrong** — we did not prove it is safe, we simply never reached the application.

**Why a false negative is worse than a false positive.** A false positive wastes an engineer's time. A false negative makes the customer believe they are safe when the flaw is still there.

## D2. How we adapt tests to the filter

1. **Fingerprint** — detect the filter and identify which product it is, before testing
2. **Select variant** — load the test profile matched to that filter
3. **On block, record `Inconclusive — filtered`** — never a clean pass
4. **Authorised retry** — where scope allows, try an alternative form to see if a real flaw sits behind the filter
5. **Backoff** — detect throttling or banning and slow down instead of losing the scan
6. **Filtered-test register** — the report lists every test the filter prevented, so gaps are visible

## D3. Hidden vs fixed (the valuable part)

**The key insight:** a firewall *hides* a flaw, it does not *remove* it.

Where the origin server is directly reachable, we test both **through the filter** and **directly at origin**, then compare:

| Result | Meaning | What the customer must do |
|---|---|---|
| Blocked at filter, **absent** at origin | Genuinely fixed | Nothing |
| Blocked at filter, **present** at origin | **Hidden, not fixed** | Fix the application — the filter is only a compensating control |

**Example.** A SQL injection flaw exists in the application. The WAF blocks the obvious attack. The customer believes it is resolved. But an attacker who finds the origin IP address connects directly, bypasses the WAF completely, and exploits the flaw. Our differential test catches exactly this.

## D4. Allow-listing and reachability (the operational half)

- **Published scanner IP ranges** — so the customer can allow-list us and recognise our traffic
- **Allow-listing confirmed in the scope agreement** — a formal step, like the test accounts
- **Reachability pre-check** — before scanning, confirm we can actually reach the target; if not, abort with a clear reason rather than produce a misleading empty report
- **Mid-scan block detection** — if the filter starts dropping us halfway, pause and notify rather than finish with silent gaps
- **Coverage statement on every report** — what was tested, what was filtered, what was unreachable

---

# PART E — DATA PROTECTION & ACCESS (Section 6 of the plan)

*This section answers the "who has access to logs, backups and config?" question. It has two halves.*

## E1. Why this matters at all

**The point to make:** logs and backups contain the **same sensitive data as the main database**, but are almost always protected far less carefully. A database might have strict access control while a backup file sits in a shared folder that half the company can read.

## E2. Half one — our own internal access control

**The principle: zero standing access.** Nobody on our team has routine permission to read customer logs, evidence, configuration or backups. Access is granted per incident, not per role.

| Control | What it means in practice |
|---|---|
| **Zero standing access** | Engineers work against metadata and synthetic data by default |
| **Break-glass** | Real access is time-boxed, reason recorded, approved by a second person, expires automatically |
| **Separation of duties** | Whoever administers the infrastructure cannot grant themselves data access |
| **Per-tenant encryption** | Each customer's data has its own keys — no single key opens everything |
| **Immutable audit log** | Every read, export, restore or delete is recorded in a log operators cannot edit |
| **Customer-visible access log** | The customer can see which of our staff opened their data, when, and under whose approval |
| **Secrets vault** | Credentials and tokens never appear in logs, evidence, error traces or support tickets |
| **Backup controls** | Encrypted; restoring requires two-person approval; restores are audited |
| **Retention and erasure** | Automatic — see Part F |

**Why the customer-visible access log is a differentiator.** Every vendor says "trust our internal controls." We show the log. That converts a promise into evidence.

## E3. Half two — testing the customer's own hygiene

A new defensive check family, delivered mainly through the Linux agent.

**Access review — who can reach these files:**

| Check | Real-world example |
|---|---|
| Log file permissions | `/var/log/app.log` readable by every user on the server |
| Log delete rights | A low-privilege account can erase logs — **an attacker can destroy the evidence of their own activity** |
| Backup permissions | `backup.sql` readable by the web server user |
| Config permissions | `config.php` containing the database password, readable by any service account |
| Privilege review | Which accounts can escalate and read all of the above |
| Service account scope | The application account has far broader read access than the application needs |

**Exposure review — reachable from outside:**

| Check | Real-world example |
|---|---|
| Backups in web paths | `https://site.com/backup.sql` downloads the whole database |
| Config files exposed | `.env` file served over HTTP, revealing credentials |
| Log endpoints exposed | A debug or log viewer reachable with no login |
| Secrets in retrievable files | API keys inside a file the scanner can fetch |
| Backup encryption | Backups stored unencrypted |
| Retention and integrity | Retention below the legal requirement; logs not tamper-evident |

**Output:** an access matrix per file type — who can read, write, export, delete — plus exposure findings. This doubles as evidence for the customer's own compliance obligations.

---

# PART F — COMPLIANCE (Section 10 of the plan)

## F1. CERT-In — four obligations

CERT-In Directions 2022, binding on essentially every entity running digital infrastructure in India.

| Obligation | Detail |
|---|---|
| Incident reporting | Specified incident classes reported **within 6 hours** of becoming aware |
| Log retention | ICT system logs kept **180 days**, stored **within India** |
| Clock synchronisation | System clocks synced to NIC or NPL time servers |
| Information requests | Respond to CERT-In requests within 6 hours |

## F2. DPDP — what it actually is

**DPDP** = Digital Personal Data Protection Act 2023, with the **DPDP Rules 2025** adding the operational detail. It is India's personal-data protection law.

**Key terms:**

| Term | Meaning |
|---|---|
| **Data Principal** | The individual the data is about |
| **Data Fiduciary** | The organisation deciding how the data is processed — **this is us** |
| **Significant Data Fiduciary (SDF)** | A larger or higher-risk Fiduciary, designated by government, with extra duties |

**What DPDP requires of us:**
- Reasonable security safeguards — **encryption, masking, strict access controls**
- **System and processing logs kept a minimum of one year**
- Breach notification (see F4)
- Retain data only as long as its purpose requires, then erase it

## F3. The retention conflict — and why the answer is one year

| Regulation | Requirement |
|---|---|
| CERT-In | 180 days, stored in India |
| DPDP Rules 2025 | **Minimum 1 year** for system and processing logs |

**Both apply to us. When two obligations overlap, you comply with the stricter one. So: one year.**

**The consequences we accepted:**
- Storage roughly doubles, so we use tiered storage (recent logs fast, older logs archived and cheap)
- India residency becomes a **Phase 1** architectural decision, not a later feature
- It cannot be retrofitted — logs already deleted are gone forever
- Write-once handling for security logs, so retention is defensible

## F4. Two breach clocks

| | CERT-In | DPDP |
|---|---|---|
| Tell whom | CERT-In | Data Protection Board + affected individuals |
| Deadline | **6 hours** | Inform without delay; **detailed report in 72 hours** |

**Two separate situations:**

**Our own breach** — non-negotiable. We notify under both. A tested runbook and templates are Phase 1.

**Customer breach** — phased:
- **Phase 1-2: alert + template.** We detect, notify them, start a visible countdown against both deadlines, hand them a pre-filled template and evidence pack. They file.
- **Phase 3+: assisted filing.** We generate the complete submission for their approval.

**Why staged:** alerting has clean responsibility boundaries. Filing on their behalf shifts liability if it is wrong or late. Build it — but settle the contract first.

## F5. SDF — built ready, not assumed

If we are designated a Significant Data Fiduciary, three duties apply:
- A **DPIA** (Data Protection Impact Assessment)
- An **independent audit every 12 months**
- A **named Data Protection Officer**

**Our position:** we do not assume designation, but we build so designation does not force a redesign. We maintain a DPIA anyway, keep evidence continuously audit-ready, and name an internal privacy owner from Phase 1.

**Why:** a platform holding security findings on many companies is exactly the profile that attracts designation as it grows. Preparing early is cheap; retrofitting under a deadline is not.


## F6. IoT compliance stack

| Layer | Standard | Purpose |
|---|---|---|
| Indian baseline | **TEC 31318:2021** | The governing Indian code of practice for consumer IoT |
| International baseline | **ETSI EN 303 645 v3.1.3** | The 13 provision families TEC is built on |
| How to test it | **ETSI TS 103 701** | Defines the conformance assessment method |
| Device certification | **MTCTE** | India's mandatory testing and certification |
| Attack coverage | OWASP IoT Top 10 / FSTM | Our offensive playbook grounding |

**The leverage point:** because TEC is built on ETSI, **one test suite serves both India and international markets** — the UK, Singapore and Australia use the same baseline.

**Three provisions anchor our scanning:** no universal default passwords; a vulnerability-disclosure mechanism; keep software updated. All three map to checks we already planned.

---

# PART G — THE LINUX AGENT

## G1. What it is

A small read-only program installed on the customer's Linux server. It collects facts and sends them to us.

**Design rules:** read-only, least privilege, **outbound-only connections** (opens no inbound ports — important for their firewall team), signed binaries, resource-capped, clean uninstall, one-time enrolment token.

## G2. Why it matters — the backport problem

**For example:**
From outside, we see a banner saying "Apache 2.4.41". We look up that version and find 12 known vulnerabilities. We report 12 issues.

**But Linux distributions backport security fixes without changing the version number.** The real server may have 10 of those 12 already patched — the version string simply does not reflect it.

So our external scan just produced **10 false positives**. That destroys trust, and our whole promise is accuracy.

**With the agent:** we read the actual package database and see precisely which patches are applied. Near-zero false positives.

**The one-line version:** *"Version strings lie. The agent reads the truth."*

---

# PART H — WHY WE ARE DIFFERENT

## H1. The four unique differentiators

**1. Confidence score, separate from severity.**
Everyone reports how *severe* something is. Nobody reports how *sure* they are.
*Example:* we show "Critical · Confidence 96% · confirmed by independent re-test." We sort the queue by Risk x Confidence — a 95%-confidence High deserves attention before a 40%-confidence Critical.

**2. Honest "Inconclusive" reporting.**
Five states: Confirmed, Highly Likely, Suspected, Informational, **Inconclusive**.
*Example:* "We could not test this because the WAF filtered it" is reported openly instead of being silently counted as a pass. No competitor admits uncertainty, and experienced security people trust it immediately.

**3. Chokepoint analysis.**
*Example:* instead of 20 separate findings, we say "fix this one authentication gap and 6 of the 8 attack paths disappear." That is the question a manager actually has.

**4. Standards-based transparent playbooks.**
Auditable coverage (OWASP, MITRE, PTES) rather than an opaque "50 checks".

## H2. Supporting differentiators

| Differentiator | Why it matters |
|---|---|
| Evidence shown, not just verdicts | Developers argue with scanners; they do not argue with a recording of their own server returning someone else's data |
| Free fix verification | We re-run the exact proving test and close the finding with evidence. Never charge to check whether a fix worked |
| Ground-truth via agent | Real patch state, not version guesses |
| **Concurrency coverage** *(new)* | A defect class single-request scanners structurally cannot find |
| **Hidden vs fixed** *(new)* | We distinguish "remediated" from "concealed behind a filter" |
| **Customer-visible access log** *(new)* | The customer sees who at our company touched their data |
| Import external findings | Their existing tools' results deduplicated against ours |

---

# PART I — AI / LLM STRATEGY

**Where AI is used:** explaining findings in plain language, tailoring an explanation for a developer vs a manager vs an auditor, summarising a scan, suggesting what to test next.

**Where AI is NOT used:** running tests, deciding verdicts, taking any action.

**The three-step plan:**

| Stage | Choice | Reason |
|---|---|---|
| Prototype | Free hosted tiers (Groq, Google AI Studio) | Zero cost while building. **Never customer data on a free tier** |
| Production | **Self-hosted Qwen3** (Apache 2.0) | Data never leaves our infrastructure; no per-token cost; supports our India residency obligation; becomes a selling point |
| Fallback | A cheap paid API kept configured | A rate limit must never break production |

**The strategic line:** *"Because AI only advises, we are not locked to any model. Swapping later costs us almost nothing."*

---
# Decision Log — What Changed and Why

Four points were raised in review. Each has been resolved and folded into the architecture. Where a point could be read two ways, both readings turned out to be complementary rather than alternatives — so both were adopted, with the cheaper one riding on infrastructure the other requires.

| # | Point raised | Decision taken | Rationale | 
|---|---|---|---|
| 1 | Who has access to logs, backups and configuration data? | **Both readings adopted.** (a) A formal internal access-control model for our own platform, and (b) a new customer-facing test family that audits *their* log/backup/config access hygiene. | (a) is mandatory — DPDP Rules require strict access controls, and we will hold customer logs and evidence. (b) is low additional cost once the Linux agent exists, and it is a finding customers rarely self-check. | 
| 2 | Concurrency is missing from test scope | **Both classes adopted.** (a) Race conditions / TOCTOU, and (b) concurrent session handling. | (b) is nearly free — the multi-identity session manager built for RBAC is exactly the machinery required. (a) is the higher-value class and where real financial and logic defects live. | 
| 3 | How do you modify test cases according to firewall configuration? | **Both parts adopted.** (a) Technical: fingerprint the filter, select a matched test variant, and report *Inconclusive — filtered* rather than a false pass. (b) Operational: scanner allow-listing becomes a formal pre-scan approval with a reachability check. | (a) prevents false negatives, which are more damaging than false positives because the customer believes they are safe. (b) prevents wasted scans and silent partial coverage. Added beyond the question: differential testing with the filter in and out of path, to separate *fixed* from *hidden*. | 
| 4 | DPDP is mandatory | **Committed, not optional.** Three consequences resolved: log retention standardised at **1 year**; dual breach-notification clocks implemented; platform designed **SDF-ready** without assuming SDF designation. | CERT-In requires 180 days, DPDP Rules require a minimum of 1 year for system and processing logs. Where obligations overlap, the stricter governs — so 1 year. SDF status is designated externally, so we build so designation does not force a redesign. | 

**Net effect on schedule:** approximately neutral. The concurrency work is largely absorbed by existing session infrastructure, and the firewall operational work is process rather than engineering. The genuine additions are the internal access-control model and the extended retention architecture, both of which are Phase 1 by necessity.

**What did not change:** the dual-mode architecture, the shared core, the flow engine, the four differentiators, the Linux-first agent decision, and the self-hosted model strategy all carry forward intact.
