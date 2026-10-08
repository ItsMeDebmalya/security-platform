# 09 — Ownership Verification

*The mechanism that stands between us and criminal liability. It gates every check declared active, whatever mode it runs under, starting with the first one — which is well before the website exists.*

> Written because the audit found this specified nowhere in operational detail, despite four documents referring to it as a hard gate.

---

## Why this exists

Active scanning of a system you do not own is a criminal offence under the US Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents almost everywhere. "The customer told us they owned it" is not by itself a defence. What protects us is a **documented, reasonable-effort verification with an auditable record.**

This is not a Phase 6 feature. The moment a Standard-mode check runs against a domain we do not personally own — including a founder-run demo scan during customer validation — this mechanism must already exist.

---

## Verification by target type

The methods commonly listed for this (DNS TXT, file upload, meta tag, email) are all *domain*-ownership proofs. **They do not work for IP or CIDR targets**, which are a first-class target type for the Network Scanner. That gap is closed here.

### Domain / URL targets

| Method | How | Strength |
|---|---|---|
| **DNS TXT** | Customer publishes `_scanverify.<domain> TXT "sp-verify=<nonce>"` | Strongest. Requires zone control. **Default.** |
| **HTML meta tag** | `<meta name="sp-verify" content="<nonce>">` on the root document | Strong. Requires content control. |
| **File upload** | `/.well-known/sp-verify-<nonce>.txt` | Strong. Requires content control. |
| **Email to a registrar/RDAP contact** | Nonce to the address in RDAP, or to `admin@`/`security@` | Weaker. Use only as a fallback. |

Verifying `example.com` does **not** verify `sub.example.com` unless the customer requests wildcard scope explicitly and the TXT record is placed at the apex. Subdomains discovered by enumeration are **not** automatically in scope — enumeration is passive and permitted; scanning what it finds is not.

### IP / CIDR targets

| Method | How | Strength |
|---|---|---|
| **RDAP / WHOIS registrant match** | The block's registrant or abuse contact matches the verified org, confirmed by nonce to that contact | Strong |
| **Reverse-then-forward DNS chain** | PTR resolves to a hostname in an already-verified domain, and that hostname resolves back to the IP | Moderate — use with a second method |
| **Signed attestation + abuse-contact notice** | Countersigned authorisation naming the exact ranges, plus a notification to the RIR abuse contact | Required for cloud-hosted IPs where the customer is not the registrant |

**The cloud case is the common one and the awkward one.** A customer's EC2 address is registered to AWS, not to them. Ranges inside a cloud provider require the signed attestation route *and* compliance with that provider's own penetration-testing policy, which must be checked per provider before any Standard network scan.

### Cloud accounts and repositories

Ownership is proven by the access grant itself — a read-only role the customer creates in their own account, or an OAuth grant against their own repo. The audit record stores the grant, not a nonce.

---

## Lifecycle

1. **Request** — org, target, requested methods, requester identity.
2. **Challenge** — generate a single-use nonce, valid 7 days.
3. **Proof** — we check for it; every attempt is logged, successful or not.
4. **Verified** — an authorisation record is written.
5. **Expiry** — **valid 90 days**, then re-verification. Domains change hands; a two-year-old TXT check is not evidence about today.
6. **Re-verification** — automatic re-check before any scheduled scan whose authorisation is more than 90 days old. Failure suspends scanning of that asset rather than deleting the asset.
7. **Revocation** — immediate, by the customer or by us. Revocation cancels running scans via the kill switch.

**Continuous monitoring** (Attack Surface Monitor, Deface Monitoring) re-verifies on the same 90-day cycle. A monitor whose verification lapses pauses; it does not silently continue.

---

## The authorisation record

Immutable, append-only. This is the artefact produced if anyone ever asks by what right we touched a system.

```jsonc
{
  "authz_id": "authz_01J8…",
  "org_id": "org_…",
  "target": { "type": "domain", "value": "example.com", "wildcard": false },
  "method": "dns_txt",
  "nonce": "sp-verify=…",
  "proof": {
    "observed": "sp-verify=… (TXT at _scanverify.example.com)",
    "resolver": "1.1.1.1", "observed_at": "…",
    "raw_response_ref": "s3://…"        // the actual DNS answer, retained
  },
  "verified_at": "…", "expires_at": "…",
  "verified_by": "system|operator:<id>",
  "requester": { "user_id": "…", "ip": "…" },
  "attestation_ref": null,               // signed doc, for Deep mode and IP ranges
  "revoked_at": null, "revocation_reason": null
}
```

Every `ScanRun` carries `authz_ref` pointing at this record. **A run whose checks include even one declared-active check cannot execute without an `authz_ref`, in any mode** — `core/authz.py` denies by default, and this is the check it performs.

Retain authorisation records for **7 years**. They are our defence, and they outlive the customer relationship.

---

## The interim mechanism, before Phase 6

Until self-serve verification exists, the same rules apply through an operator-maintained file. It is not a lower standard — only a manual one.

`config/authorised_scope.yaml`:

```yaml
- authz_id: authz_2026-08-22-001
  org_id: org_internal
  target: { type: domain, value: example.com, wildcard: false }
  method: dns_txt
  proof:
    observed: 'sp-verify=7f3a… at _scanverify.example.com'
    observed_at: 2026-08-22T09:14:00Z
    evidence_file: corpus/authz/example.com-2026-08-22.txt
  verified_at: 2026-08-22
  expires_at: 2026-11-20
  verified_by: operator:<name>
  attestation_ref: null
```

Rules for the interim file:
- **The gate is per check, not per mode** ([03-roadmap.md](03-roadmap.md) 0b.6). `core/authz.py`'s `authorise()` used to key entirely on `mode` — Light exempt, Standard/Deep gated — and that was wrong for email: every email Standard check only ever reads public DNS, yet it sat behind the gate anyway. A scanner with a `Check` catalogue (`scanners/*/checks.py`) now declares `passive: bool` on every check it owns, with no default, and `core/authz.checks_require_authorisation()` asks the catalogue rather than trusting the mode label. **What "passive" means:** what an ordinary client does — one normal connection, nothing the target would not serve to any visitor. **Active** is deliberately abnormal input — offering obsolete protocols or a weak/legacy cipher list to see what a server will accept, not what it ordinarily negotiates, or sending payloads. A connection to the target is not itself what makes a check active; the roadmap's own example makes this precise: "finding a server is passive, reading its admin panel is not," and finding a server requires connecting to it. **The practical effect today:** the email scanner needs no authorisation in Standard mode any more than in Light — the product-wide contract that Light needs none stays exactly what it was. Since [ADR-023](02-decisions.md#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active), the same holds for TLS in every mode. Completing a handshake at an obsolete protocol or with a legacy cipher list is ordinary negotiation, not malformed input, so every TLS check is passive. **No check in a shipped scanner (`email`, `tls`, `domscout`, `web`) is active today**, so no real scan reaches the deny path yet; only the reference `example` scanner, which falls back to the mode rule, does. See `docs/12-cli-runbook.md` for a real transcript.
- **A scanner that has not migrated is unaffected.** `BaseScanner.requires_authorisation()` defaults to `None` — "no declaration" — which falls back unchanged to the old mode-based rule. `None` is never treated as "passive"; the only way to skip authorisation is an explicit `passive=True` traced to a specific check.
- **Standard and Deep still deny by default** for any check declared active, in whatever mode it runs under. No entry, expired entry, or revoked entry means the scan does not run.
- Every edit is a reviewed commit. The git history *is* the audit log.
- The evidence file (the actual DNS answer or HTTP response proving the nonce) is committed alongside. A row asserting verification without its proof is not verification.
- Targets we personally own may be marked `method: self_owned` with a note — still an explicit row, never an implicit exemption.

---

## What this does not cover

Stated plainly so nobody mistakes verification for blanket legal cover:

- **A customer who lies.** Verification proves control of a DNS zone or a web root, which is strong evidence of authority but not proof of legal ownership. A subtenant, a departing contractor, or a compromised account can all pass. Reasonable effort is our defence; it is not immunity, and the ToS must place the warranty of authority on the customer.
- **Third-party scanning.** Vendor-risk scanning targets companies who never consented. It must be **passive only**, forever. See [07-open-questions.md](07-open-questions.md).
- **Damage.** Verification authorises the scan; it does not limit liability if the scan breaks something. That is a ToS, indemnity and insurance question.
