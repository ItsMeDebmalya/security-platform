# 11 — Operations, Incident Response and Observability

*What happens when things go wrong. Stub-level for now, because none of it is needed for Phase 0 — but tracked, because the absence of any plan here was a real gap and CSPM will eventually have us holding customer cloud credentials.*

---

## The four incidents that actually happen to scanning companies

### 1. We break a customer's production system

The likeliest serious incident. A scan overwhelms an under-provisioned target, trips a WAF into blocking legitimate traffic, or fills a log partition.

**Prevention** (all in `core/`, all from Phase 0): conservative per-host token bucket, adaptive backoff on rising latency or 429/503, global concurrency cap per target org, kill switch checked between every request.

**Response runbook:**
1. Kill the scan — per-scan switch, seconds not minutes.
2. Escalate to the org-level switch if the blast radius is unclear.
3. Preserve the `ScanRun` record and full request log; do not delete anything.
4. Notify the customer *before* they notice, with the exact request rate and timeline.
5. Post-incident: what rate did we send, what did the target's capacity turn out to be, does the default bucket need lowering.

**Commercial exposure:** the ToS must address liability for scan-caused outages. Not resolved — see [07-open-questions.md](07-open-questions.md).

### 2. Our scanner IPs get blocklisted

Not "if." Cloudflare, Akamai, and corporate WAFs will eventually classify us as hostile.

**Prevention:** publish our IP ranges with a page explaining who we are; register with major WAF vendors' crawler-verification programmes where they exist; identify honestly in the user agent; honour a documented opt-out for passive scanning.

**Response:** detect blocking as a first-class scanner outcome (a challenge page is `inconclusive`, never a fingerprint of the customer's stack); maintain a small pool of ranges so one blocklisting is not total; request delisting with evidence of our rate limits. **Never rotate IPs to evade blocking** — that is indistinguishable from attacker behaviour and would destroy the legal posture the whole product rests on.

### 3. We are breached while holding customer cloud credentials

The highest-severity possible incident. Cloud CSPM has us holding read-only roles into customer AWS/Azure/GCP accounts; the Code Scanner has us holding repository grants.

**Prevention:** read-only roles only, never long-lived keys, never write access. External-ID-scoped role assumption per customer. Short-lived credentials fetched per scan, never stored at rest. Scan workers sandboxed with restricted egress. Credentials never logged, never in evidence, never in error messages.

**Response:** revoke every role grant platform-wide before investigating — customers can re-grant, but a live credential during an active breach is unbounded loss. Then notify every affected customer with what the role could reach, and preserve worker images and logs.

**Regulatory:** GDPR Article 33 requires notification within 72 hours where personal data is involved.

### 4. Someone abuses the free tier

Unauthenticated Light scanning of arbitrary domains, from our IPs, at our cost — usable for reconnaissance against third parties, or to make us look like the attacker.

**Mitigations to choose between** (unresolved, see [07-open-questions.md](07-open-questions.md)): per-IP rate limits, captcha, results visible but signup required to export or persist, small daily per-IP quota. Regardless of choice: log every free scan with source IP and target, and support target-side opt-out.

---

## Observability

Nothing beyond "progress to stderr" is needed for Phase 0. Before Phase 3 (when monitoring puts us in continuous contact with external systems):

- **Structured logs**, JSON, with `scan_id` and `org_id` on every line. Never log credentials, cookies, auth headers, or evidence bodies.
- **Per-scan metrics** — requests sent, bytes, wall time, findings by state, inconclusive rate, backoff events, kill-switch trips.
- **Fleet metrics** — scans queued/running/failed, per-target-host error rates (a spike means we are hurting someone), browser context count and memory.
- **Alerts** — any kill-switch trip, sustained 5xx from a target, any scan exceeding its cost budget, any authorisation check failing open (should be impossible; alarm if it happens).
- **Cost per scan** tracked from the first scan — requests, wall time, AI tokens. Without it we discover our margins too late to fix them.

---

## Secrets management

The plan covers redacting *customer* secrets thoroughly. It said nothing about our own.

Ours include: paid data-provider API keys (Censys, SecurityTrails, VirusTotal), AI provider keys, OOB server auth, cloud role external IDs, and signing keys for verification nonces.

Baseline: no secrets in the repo, ever, including test fixtures; `.env.example` documents every key with no values; local development uses a local file that is git-ignored; production uses the platform's secret manager with per-environment separation and rotation on any suspicion. Third-party binaries in `tools/` are pinned by checksum so a compromised upstream release cannot silently substitute itself.

---

## Data retention

Findings and evidence can incidentally contain customer production data — real row counts, real error messages, and in the case of OSINT harvesting, personal data about people who never consented.

Provisional policy, pending the legal review:

| Data | Retention |
|---|---|
| Findings (metadata, no bodies) | Life of the account + 90 days |
| Evidence bodies and screenshots | **90 days**, then purged; the finding survives with its delta summary |
| Authorisation records | **7 years** — our legal defence |
| Scan run telemetry and cost | 2 years |
| OSINT-harvested personal data | **Shortest defensible period; not yet determined.** Blocks the OSINT feature. |
| Raw free-tier scan logs | 30 days |

Right-to-erasure needs a working deletion path *including object storage*, and that is not trivial once evidence is spread across blobs. Design it before Phase 6, not after the first request arrives.
