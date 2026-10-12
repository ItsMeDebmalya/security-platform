# 01 — Architecture

*The Scanner Contract, the finding model, and how it grows into a platform. This is the document that stops the tool-first strategy producing an unmergeable pile.*

> **Revision note (v3.1):** the Finding schema in this document was audited before freezing and three blocking gaps were fixed — a missing `ScanRun` entity and `status` field, an ID formula that collided on multi-instance and location-less findings, and a state-derivation rule that was prose rather than a function. See [08-changelog.md](08-changelog.md).

---

## The core idea

Every scanner is a **module that satisfies one contract**. Nothing else in the system knows or cares what a scanner does internally.

```
                        ┌──────────────────────────┐
   target + mode  ──▶   │      SCANNER MODULE      │  ──▶  ScanResult (JSON)
   + config             │  (email / tls / dns /    │       ├─ findings[]
                        │   web / net / api / …)   │       ├─ errors[]
                        └──────────────────────────┘       └─ telemetry
```

Because the contract is fixed, three things become true:

1. A scanner can be built, run and tested completely standalone — from a terminal, today, with no website in existence.
2. The website, when we build it, is a *thin wrapper*: authenticate, authorise the target, enqueue, run the same module, store the same JSON.
3. Any scanner can be swapped, rewritten in another language, or replaced by a third-party tool wrapper without touching anything else.

**The contract is frozen before tool #1 is written.** Changing it later means migrating every scanner and every stored finding. Treat a contract change like a database migration — see [06-guidelines.md](06-guidelines.md).

---

## Repository layout

```
security-platform/
├── docs/                       # this document set
├── contracts/
│   ├── finding.schema.json     # THE finding schema — single source of truth
│   ├── scanrun.schema.json
│   ├── scanresult.schema.json
│   └── evidence.schema.json
├── core/
│   ├── models.py               # typed objects generated from / validated against the schemas
│   ├── scanner.py              # BaseScanner — the interface every tool implements
│   ├── registry.py             # name → scanner class lookup
│   ├── http.py                 # the ONE http client (rate limits, UA, proxy, recording)
│   ├── dns.py                  # the ONE dns client
│   ├── confidence.py           # confidence calculation + calibration
│   ├── state.py                # the state-derivation function (see below)
│   ├── evidence.py             # evidence capture and redaction
│   ├── ratelimit.py            # token bucket, adaptive backoff
│   ├── authz.py                # scope enforcement — is this target in bounds
│   └── killswitch.py           # global and per-scan stop
├── scanners/
│   ├── email/                  # tool 1
│   ├── tls/                    # tool 2
│   ├── dns_enum/               # tool 3
│   ├── web_light/              # tool 4
│   └── …                       # one directory per tool, self-contained
├── corpus/
│   ├── targets/                # ground-truth target definitions per scanner
│   ├── fixtures/               # frozen recorded responses for offline replay
│   └── expected/               # the known-correct answers
├── payloads/                   # the payload library — versioned, curated
├── tools/                      # vendored third-party binaries + version pins
├── cli/                        # `scan` command
└── tests/
```

**Rule:** a scanner directory may import from `core/` and `payloads/`. It must **never** import from another scanner directory. If two scanners need the same logic, it moves to `core/`.

---

## The Scanner Contract

### Interface

```python
class BaseScanner:
    name: str                    # "email", "tls", "web"
    version: str                 # semver — bump when results change
    supported_modes: set[Mode]   # {LIGHT, STANDARD, DEEP}
    target_types: set[str]       # {"domain", "url", "ip", "cidr", "repo", ...}

    def validate(self, target: Target) -> None:
        """Reject targets this scanner cannot handle. Raises."""

    def run(self, target: Target, mode: Mode, ctx: ScanContext) -> ScanResult:
        """Do the work. Must be cancellable via ctx.killswitch.
           Must emit progress via ctx.progress(). Must never exceed ctx.ratelimit."""
```

`ScanContext` carries everything ambient: the rate limiter, the kill switch, the HTTP/DNS clients, the OOB callback client, the progress reporter, the cost meter, and the authorised scope. **A scanner never constructs its own HTTP client.** That is how rate limiting, request recording and the kill switch stay guaranteed rather than hoped for.

### Modes are additive

`STANDARD` returns everything `LIGHT` returns, plus more. `DEEP` returns everything `STANDARD` returns, plus validation. Never a different answer for the same check at a higher mode — only more checks, and higher confidence.

---

## The ScanRun

A finding is a *thing we believe about a target*. A scan run is *one execution*. They have different lifetimes and both need identity — findings persist across runs, runs do not.

```jsonc
{
  "scan_id": "01J8…",                // ULID, sortable by time
  "org_id": "org_…",                 // present from migration #1, pre-multi-tenancy
  "target": { "type": "domain", "value": "example.com" },
  "mode": "light",
  "scanners": [ {"name": "email", "version": "1.2.0"} ],
  "started_at": "…", "finished_at": "…",
  "outcome": "succeeded",            // succeeded | partial | errored | killed
  "authz_ref": "allowlist:2026-08-01#example.com",   // what authorised this run
  "cost": { "requests": 41, "wall_ms": 8300, "ai_tokens": 0 }
}
```

`ScanResult` is what a single scanner returns *within* a run: `findings[]`, `errors[]`, `telemetry`. The run aggregates results from every scanner it invoked.

### The asset graph

*Added v3.4 — [ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other).*

A run carries a shared **asset graph**. Scanners contribute what they discover and read what others found, through `ScanContext`. **Scanners still never import one another** — the run passes *data*, never control, which is what keeps each one replaceable and testable alone.

```
ScanRun
  └── AssetGraph            discovered assets + how each was found
        ▲            ▼
   dns_enum      tls · web · ai_exposure
```

Three rules make it safe:

- **Provenance is mandatory.** Every asset records the scanner that found it and the evidence. An asset with no provenance is a bug, not a discovery — scanning something we cannot explain finding is the exact failure the authorisation gate exists to prevent.
- **Authorisation is re-checked per asset.** Discovery does not confer permission. `core/authz.py` is not bypassed by the graph.
- **Consuming is optional.** A scanner handed no graph scans its own target and behaves as it does today, so nothing becomes order-dependent by accident.

**Findings reference runs, not the other way round:** `first_seen_scan_id` and `last_seen_scan_id`. That is what makes "what changed since last scan" a cheap query and what gives every status transition a provenance.

---

## The Finding model

This is the centre of the product. Get it right once.

```jsonc
{
  "id": "sha256:…",                  // deterministic — see below
  "org_id": "org_…",
  "scanner": "email",
  "scanner_version": "1.2.0",
  "check_id": "dmarc-policy-none",   // stable identifier for this specific check
  "renamed_from": [],                // former check_ids — preserves history across renames
  "title": "DMARC policy is set to 'none'",

  "target": { "type": "domain", "value": "example.com" },
  "location": "_dmarc.example.com",  // where precisely; "$" = the target as a whole
  "instance_key": null,              // discriminator when one check fires repeatedly
                                     // at one location (e.g. a payload_id)

  "severity": "medium",              // critical | high | medium | low | info
  "confidence": 0.97,                // 0.0–1.0
  "confidence_provisional": true,    // true until the check is calibrated
  "state": "confirmed",              // DERIVED — never hand-set. See truth table below.

  "detection_methods": [             // list, not scalar — the confidence engine needs
    { "method": "dns_txt_parse",     // to know what corroborated what
      "likelihood_ratio": 12.0,
      "independence_class": "dns" }
  ],
  "validation": {
    "attempted": true,
    "outcome": "passed",             // passed | failed | unavailable | not_applicable
    "method": "independent_reparse"
  },

  "evidence": [ /* see below */ ],
  "related_assets": [                // for Phase 4 correlation — see note below
    { "type": "domain", "value": "example.com", "relation": "observed_on" }
  ],

  "status": "open",                  // open | closed | accepted_risk | false_positive
  "status_history": [],              // populated from Phase 6; field exists from day one

  "description": "…", "impact": "…", "remediation": "…",
  "references": ["https://…"],
  "taxonomy": { "cwe": ["CWE-1021"], "owasp_web_2025": ["A05"] },

  "first_seen": "…", "first_seen_scan_id": "01J8…",
  "last_seen":  "…", "last_seen_scan_id":  "01J8…",
  "cost": { "requests": 3, "wall_ms": 412, "ai_tokens": 0 }
}
```

### When a finding becomes true, and where it came from

*Added v3.4 — [ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived).*

```jsonc
"materialises_at": null,            // true now. The default, and almost everything.
"materialises_reason": null,
"derivation": "detected",           // detected | derived
"derived_from": null                // the finding this was computed from
```

**`materialises_at` is a fourth axis, not a sixth state.** A certificate that is 200 days long is a fact we are certain of today; what changes in March 2027 is not our confidence but the world's rules. `severity` therefore means *how bad it will be when it lands*, and the five states keep their existing meanings. The truth table does not move.

**`derivation` separates observing from calculating.**

- **`detected`** — we looked at the target. Confidence comes from the engine below: priors, likelihood ratios, independence classes. Evidence is a control-vs-test pair.
- **`derived`** — we applied a rule to something already detected. Confidence is **inherited from `derived_from`, never recalculated.** Evidence is the premise, the rule, and the arithmetic shown.

The inheritance rule is the important half. A calendar date is not evidence; forcing it through a likelihood ratio would mean inventing a number to clear the reporting threshold. And a conclusion cannot be surer than its premise: if we are 0.97 confident we read the certificate, we are 0.97 confident of everything computed from it. That is what stops a certain-sounding claim laundering an uncertain observation.

### Severity vs confidence vs state — three separate axes

The single most common mistake in scanners is collapsing these. Keep them apart.

- **Severity** — how bad it would be *if true*. A property of the vulnerability class and its context. Never adjusted for how sure we are.
- **Confidence** — how sure we are that it *is* true.
- **State** — a derived label, computed by `core/state.py`. **Scanners never set it by hand.**

### The state-derivation function

State is a pure function of confidence, validation outcome, and detection-method independence. Written as a truth table so two scanner authors cannot disagree:

| Condition | State |
|---|---|
| Check ran but reached no verdict (timeout, WAF block, blocked prerequisite, OOB unavailable) | `inconclusive` |
| True but not directly dangerous (`severity: info`) | `informational` |
| `validation.outcome == "failed"` | `suspected`, confidence capped at 0.5 |
| `validation.outcome == "passed"` **and** confidence ≥ 0.95 | `confirmed` |
| ≥ 2 detection methods with **different** `independence_class` agree, confidence ≥ 0.75 | `highly_likely` |
| Confidence ≥ 0.75 but all methods share one `independence_class` | `suspected` — one signal, restated |
| Confidence 0.40 – 0.75 | `suspected` |
| Confidence < 0.40 | not reported as a finding; logged to telemetry only |

Two consequences worth stating plainly: **`confirmed` requires validation to have actually run and passed** — a high score alone never earns it. And three variants of one technique agreeing is one signal, not three; that is what `independence_class` exists to prevent.

**`inconclusive` is a first-class result, not an error.** A scanner that times out, gets blocked, or hits an ambiguous response must say so. Silently dropping it is the behaviour that destroys trust.

**Triage order is `severity_weight × confidence`.**

### Scan errors vs inconclusive findings

A rule, because the corpus harness cannot compute anything without it:

- A **scan-level error** means the scanner could not execute at all — crash, pre-flight unreachable, auth failure. It goes in `errors[]`, produces **zero** findings, and the run's outcome is `errored`.
- A check that **ran but could not reach a verdict** emits an `inconclusive` finding for its `check_id`. It is never silently omitted.

Without this, the corpus cannot tell "the scanner regressed" from "the target flaked."

### Deterministic IDs

```
id = sha256(scanner + check_id + target.value + normalise(location) + (instance_key or ""))
```

- `normalise(location)` strips volatile parts (session ids, cache-busting params, ordering).
- **Location-less findings use the reserved value `"$"`**, meaning "the target as a whole." `dmarc-policy-none` on a domain is a `"$"` finding.
- **`instance_key`** discriminates when one check legitimately fires more than once at one location — typically the `payload_id`. Null when the check can only fire once.
- **`renamed_from`** carries former `check_id`s. On load, a finding whose stored `check_id` appears in a current check's `renamed_from` is treated as the same finding, so history survives a rename. Renames are a migration, not an edit.
- `scanner_version` is deliberately **not** in the ID: a re-scan after a logic change must map to the same finding, or every improvement would look like a mass close-and-reopen. When a version bump changes what a check *means* rather than how well it detects it, that is a `check_id` rename plus a `renamed_from` entry.

Group-by-root-cause (one missing header across 400 URLs) happens at display time, driven by `check_id` — the 400 findings remain distinct rows with distinct locations.

### `related_assets` and the attack-path model

Phase 4 correlation needs to relate findings *across scanners* about *different entities* — a subdomain, an IP, an IAM role, a bucket. `target` + `location` alone cannot express that, and an earlier draft of this document wrongly claimed it could.

`related_assets` is the cheap hedge: every scanner records the other entities a finding touches. It costs nothing now and means Phase 4 is a query rather than a migration. **The full attack-path data model is still unresolved and is tracked as an open question — it must be validated by the end of Phase 3, before Phase 4 work starts.**

### Vantage, engagement, links and state changes

*Added 2026-10-12, Stage A, [ADR-034](02-decisions.md#adr-034--contract-extension-stage-a-host-targets-vantage-and-engagement-tags-finding-links-state-change-fields). All optional; `null` means "not recorded", never a guess.*

```jsonc
"vantage": "external_unauthenticated",  // external_unauthenticated | authenticated | agent
"engagement": "defensive",              // defensive | offensive (the v4 plan's "mode"; `mode` means depth)
"links": [                              // this finding explains / chains_to another, by id
  { "relation": "explains", "finding_id": "sha256:…" }
],
"state_change": null                    // offensive only; refused at runtime until a later ADR
```

- **Targets.** `target.type` may be `host`, a server reported by the agent, with optional `addresses`.
- **Scanner tags.** Every scanner declares its vantage and engagement once (`BaseScanner`) and stamps them on each finding. The four shipped scanners are `external_unauthenticated` and `defensive`.
- **Links.** They are the structured finding-to-finding relation `related_assets` never was. They are not yet the full attack-path model above, which is still open.
- **State changes.** `state_change` is defined so offensive work needs no second migration. `core.applicability.enforce` refuses any result carrying one, so "we don't change targets" is enforced, not promised. The authorisation gate is the first claim enforced that way.

---

## Evidence

Evidence is what makes the product defensible. Structure it; never store a blob of text. The base shape is control-vs-test; some kinds need their own fields.

```jsonc
{
  "kind": "http_pair",
  "label": "Boolean-based SQL injection: true vs false condition",
  "control":   { "request": {…}, "response": {…} },
  "test":      { "request": {…}, "response": {…} },
  "delta":     { "status": "200 → 200", "length": "8421 → 122", "rows": "47 → 0" },
  "payload_id": "sqli/boolean/or-1-1-v3",
  "captured_at": "…",
  "redactions": ["set-cookie", "authorization"]
}
```

**Kind-specific shapes.** Not every evidence kind is a request/response pair, and forcing them into one was a defect in the first draft:

```jsonc
// oob_callback — the "control" is the absence of a callback, observed elsewhere, later
{ "kind": "oob_callback",
  "token": "abc123", "emitted_in": "param=q", "emitted_at": "…",
  "hit": { "received_at": "…", "source_ip": "…", "protocol": "dns",
           "raw_request": "…" },
  "window_s": 60, "control_tokens_unhit": ["def456"] }

// timing — a single before/after pair is not how timing is validated
{ "kind": "timing",
  "baseline_samples_ms": [102, 98, 110, …], "test_samples_ms": [5104, 5098, …],
  "n": 12, "delta_ms": 5000, "method": "welch_t", "p_value": 0.0001 }
```

Other kinds: `dns_answer`, `tls_handshake`, `screenshot`, `file_excerpt`.

**Rules:**
- Always capture a **control** alongside the **test**, in whatever form the kind allows. "The server returned an error" is not evidence.
- **Redact before storage, not before display.** We must never hold a customer's session token.
- Evidence is **replayable** — every `http_pair` exports as curl. This is what makes Request Replay nearly free later.
- Size-cap bodies (256 KB default, head + tail beyond, truncation marked).

---

## The confidence engine

Not a vibe. A calculation with two stages.

**Stage 1 — combine.** Each detection method has a prior reliability and each piece of evidence a likelihood ratio, combined in log-odds:

```
logit(P) = logit(prior[method]) + Σ log(LR[evidence_i])
```

Methods sharing an `independence_class` are collapsed to their strongest single contribution before combining — otherwise three variants of one technique masquerade as corroboration.

**Stage 2 — calibrate.** Raw scores are meaningless until validated against outcomes.

**Granularity — this is a real constraint, not a detail.** Calibration is fitted **per (scanner × detection_method)**, not per `check_id`. A small customer base generates on the order of hundreds of labels a year across ~150 checks; per-check calibration would be undersampled forever and would produce confident-looking noise.

- A bucket needs **≥ 30 labelled outcomes** before a fitted calibration replaces its hand-assigned prior. Platt-style scaling works in this small-sample regime; isotonic regression does not and must not be used below a few hundred samples.
- Below the threshold, the prior stands and `confidence_provisional` stays `true`. **For low-volume checks this may be permanent, and the UI must say so.** That is a stated limitation, not a milestone we are waiting on.
- Reported per bucket: reliability diagram and Brier score.

**The labelled dataset is the most valuable asset the company will own.** It cannot be bought. Every finding must trace to its contributing methods and evidence, or the labels are useless — which is why `detection_methods` is a list with independence classes rather than a single string.

---

## The validation engine

What turns `suspected` into `confirmed`. A separate pass after detection, never inline.

1. Detection produces a candidate.
2. Validation re-tests with an **independent method** — different payload family, different observable channel.
3. Blind/asynchronous bugs validate via **out-of-band callback**.
4. Success → `validation.outcome = passed`; state derivation may now yield `confirmed`.
5. Failure → `failed`; downgrade, do not delete. Record the attempt.
6. Cannot run → `unavailable` → `inconclusive`.

The same machinery serves **fix verification**: re-run the exact test, close with evidence. Always free.

---

## The out-of-band callback server

Prerequisite for proving a large class of bugs safely, and the reason we never need exploitation.

```
scanner                     target                    our OOB server
   │  payload containing                                    │
   │  abc123.oob.ourdomain ──▶                              │
   │                          │ resolves / requests ──────▶ │  logs hit
   │  poll for token abc123 ──────────────────────────────▶ │
   │  ◀── "hit at T, from IP, via DNS+HTTP" ────────────────│
```

Requirements: self-hosted; **separate domain** from the main product; answers **DNS, HTTP, HTTPS and SMTP** (some bugs only exfiltrate over DNS); single-use scan-scoped expiring tokens; logs source IP, timestamp, protocol and full request — that *is* the evidence.

**Build vs adopt is an open sub-decision.** [Interactsh](https://github.com/projectdiscovery/interactsh) is MIT-licensed, self-hostable on our own domain, supports all four protocols, and comes from the same team as naabu/subfinder/nuclei. Our objection to third-party OOB applies to the *public* instance, not to running our own. Evaluate self-hosting before committing to a from-scratch Go service.

**Operational detail that must be decided before Phase 2:** wildcard TLS for `*.oob.ourdomain` requires the **DNS-01 ACME challenge** — HTTP-01 cannot issue wildcards — so the server needs programmatic DNS control and an authoritative nameserver. One wildcard cert renewed every ~60 days is fine; **a cert per token would hit Let's Encrypt rate limits immediately.** The design must be wildcard-cert-based.

---

## Rate limiting and safety

Enforced in `core/`, not per-scanner, because per-scanner means eventually forgotten.

- **Token bucket per target host**, conservative by default.
- **Adaptive backoff** — rising latency or 429/503 shrinks the bucket automatically.
- **Global concurrency cap per target organisation** — 50 subdomains must not become a load test.
- **Kill switch** at three levels (one scan / one customer / everything), checked between every request.
- **Published scanner IP ranges**, so targets can identify us.
- **Scope enforcement** in `core/authz.py`: every outbound request checked, deny by default. Redirects leaving scope are not followed. An SSRF probe never targets a third party.

---

## The correlation pass

*Added v3.4 — [ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target).*

After every scanner in a run has finished, a **correlation pass** reads the findings and the asset graph and emits `derived` findings that connect them into attack stories. It runs in `core/`, imports no scanner, and is driven by curated **composition rules**.

```
   scanners/*  ──▶  findings + asset graph  ──▶  correlation pass  ──▶  derived "story" findings
                                                       │
                                                 composition rules (curated data)
```

- A story's confidence is **inherited from the weakest finding it chains** — a chain is as believable as its least certain link.
- A story orders the fix plan: a finding that links three stories outranks an isolated one of equal severity.
- A rule that cannot justify a chain does not draw it. Under-telling beats over-telling.

## Fix verification and the finding store

`scan verify <finding-id>` re-runs the single test that proved a finding and transitions its `status`. This needs findings to **persist between scans** — a finding store, which the CLI backs with a local file today and Phase 6 backs with a database, same interface. The contract already carries `status`, `status_history`, `first_seen_scan_id` and `last_seen_scan_id`; the store and the verify operation are what make them move.

## How this becomes a platform

Nothing below exists yet. It is drawn so Phase 0 does not paint us into a corner.

```
   Browser ──▶ Web app ──▶ API ──▶ queue ──▶ scan workers ──▶ scanners/*
                             │                    │              (unchanged)
                             ▼                    ▼
                         Postgres            object storage
                    findings, assets,        evidence blobs,
                    users, scan_runs,        screenshots
                    status_history
                             │
                             ├──▶ OOB callback server (separate domain)
                             └──▶ AI service (explanations, summaries)
```

- **Queue** — scans are long-running; never in a request handler. Workers stateless, horizontally scaled.
- **Workers run untrusted-adjacent work** (crawling hostile sites, cloning customer repos, unpacking customer images) and must be **sandboxed with restricted egress**. A real security boundary.

**Critical property: `scanners/` is identical in both worlds.** The CLI and the worker are two callers of one contract.

### Browser-based scanning: sizing reality

The Playwright crawler is the one component whose infrastructure cost is not obvious. Real deployments cap at roughly **3–4 concurrent browser contexts per host** on memory pressure, before accounting for JS-heavy targets. Docker's default 64 MB `/dev/shm` crashes Chromium and must be raised explicitly. Context-per-request lifecycle with `try/finally` cleanup is mandatory; leaked contexts are the most common cause of unbounded memory growth. Budget accordingly — this ceiling shapes what per-scan concurrency is achievable at all.

---

## Deferred by design

- **Multi-tenancy, RBAC, SSO** — Phase 6+. `org_id` on every row from the start so it is not a rewrite.
- **Distributed scanning from multiple regions** — later; the contract lets a worker declare its region.
- **Real-time streaming of findings** — later; scanners already emit progress events.
- **Attack path graph** — Phase 4 at the earliest, and **its data model is an open question, not a solved one** (see `related_assets` above).
