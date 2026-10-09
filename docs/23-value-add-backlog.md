# 23 — Value-add backlog

*A **plan only**. Nothing here is built, scheduled or promised. These are candidate features found during the 2026-10-08/09 live runs, and each is grounded in evidence we already hold. Status and gate numbers live in `SPEC.md` and the ledger. This file links to them and restates none.*

> **Open question (pending the operator's senior):** build the three quick wins (#2, #3 and #4) **before Tool 4b, or after?** Until that is decided, the order in `docs/03-roadmap.md` and the ledger's "Next" stands: D48, then D28/D31 with the service_hosts ADR, then Tool 4b.

**Rules every item follows, the same as a check** (ADR-017, `docs/06-guidelines.md`):
- It fires on a **real positive** before it ships. A synthetic corpus case alone is not enough.
- It is **verified live** and hand-checked.
- Its claims match its evidence. It never says what we did not observe, and it never asserts what other people's software does unless a spec says so.
- It stays inside hard constraints 1 and 5: no exploitation, nothing downloaded that we do not need, no secret stored.
- If it fires on its first real target and gets it wrong, it is BROKEN until fixed.

**Effort scale:** S is days, on code that exists. M is a week or two, or touches `core/`. L needs a contract change or new infrastructure.

| # | Feature | Effort | Status |
|---|---|---|---|
| 1 | Ready-to-paste DNS fixes (SPF/DMARC) | M | PROPOSED |
| 2 | Directory listings ranked by risk | S | PROPOSED · **QUICK WIN** |
| 3 | DNS consistency across public resolvers | S | PROPOSED · **QUICK WIN** |
| 4 | Protection for parked domains | S | PROPOSED · **QUICK WIN** |
| 5 | Group findings by fix | M | PROPOSED |
| 6 | Change alerts and fix evidence | M | PROPOSED |

---

## 1. Ready-to-paste fixes: the exact corrected DNS record

- **What it does.** For SPF and DMARC findings, the remediation gives the exact record to publish, built from the customer's own current record: the same mechanisms with the qualifier fixed, or the same DMARC record with the next stage's policy.
- **Where it came from.** Email live run 2's hand-verified DMARC and SPF findings ([verification](../corpus/crosscheck/email-live/2026-10-08-run2/verification.md)). Each one's remediation today is prose. The `?all` severity and double-count rulings are in the ledger ([email v1.2.0 entry](14-progress-ledger.md)).
- **Customer value.** The fix stops being research. The customer copies one line rather than reading RFC 7208 or RFC 9989.
- **Guardrails.**
  - **Never suggest an immediate `p=reject`.** Always give a staged rollout: `p=none`, read the aggregate reports, then `p=quarantine`, then `p=reject`. An abrupt reject can block the customer's own legitimate mail from senders they forgot to authorise.
  - Each stage names what to check before moving on: the `rua` reports show no legitimate source failing.
  - Never use `pct` for staging. RFC 9989 removed it (ledger D44). Whether to offer `t=y` instead needs its own decision, because receivers that still read RFC 7489 ignore it.
  - **Never invent an SPF mechanism.** We cannot know the customer's senders. The suggested record keeps every existing mechanism and changes only the `all` qualifier. If there is no record, we say what it must contain and do not guess an `include:`.
  - A suggested record is validated by our own parser before it is shown. It must parse cleanly, stay within the 10-lookup limit, and be a valid RFC 9989 record.
- **Effort.** M: generators for two record types, plus parser round-trip tests.

## 2. Directory listings ranked by risk · QUICK WIN

- **What it does.** When `web-directory-listing` fires, it classifies the file names in the listing we already fetched and raises the severity when a risky name appears. Risky names are database dumps (`.sql`), backups (`.bak`, `~`), environment files (`.env`) and archives (`.zip`, `.tar.gz`).
- **Where it came from.** The Tool 4a live run: `web-directory-listing` fired on an operator-owned host ([web-light verification](../corpus/crosscheck/web-light/verification.md)). The check is WORKING ([catalogue](21-scanner-catalogue.md)).
- **Customer value.** A listing of `/images/` and a listing that holds `backup.sql` are not the same problem. Today they get the same severity.
- **Guardrails.**
  - **Classify by file name only**, from the listing body we already fetched. **Never download, open or HEAD the files.** Their contents may be the customer's data, and fetching them is extraction (hard constraint 1).
  - The claim is "a file named X is listed", never "X contains a database". A name is not its content, so a name-only finding caps at `suspected` unless a second independent signal exists.
  - The listed name goes through core's redactor like any other stored text (ADR-028).
- **Evidence gap before it can ship.** The listings seen live so far hold only static-asset folders. **No risky file name has been observed live yet**, so this needs a real positive, for example a lab target from `docs/13-test-targets.md`, before it ships.
- **Effort.** S: a name classifier over the parsed listing entries, with positive and negative corpus cases.

## 3. DNS consistency across public resolvers · QUICK WIN

- **What it does.** Reports when a domain's SPF, DMARC or DKIM records differ between public resolvers. A receiver behind the resolver with the wrong answer may then reject or misclassify legitimate mail.
- **Where it came from.** D39's measurement in email live run 1 ([ledger, 2026-10-08 run 1](14-progress-ledger.md#2026-10-08--email-live-run-1-resolver-disagreement-measured-hand-verification-on-hold-d39)): a public resolver returned icicibank.com's TXT set without its SPF record, while two others returned it. That became corpus case `disagree-stale-spf` ([D39](14-progress-ledger.md#d-deferred-register)). Since D39, core routes a query to the resolver it names, so the check is buildable.
- **Customer value.** A record that is right at the authoritative server but wrong in part of the world's caches fails quietly, for some receivers only. Single-resolver scanners cannot see it.
- **Guardrails.**
  - **Report only a difference that persists after a retry past the record's TTL.** Changes that are still propagating are normal and must never be flagged.
  - The finding names each resolver and the exact answer it gave. Each answer is labelled with the resolver that actually answered (D39).
  - A timeout or SERVFAIL is not a disagreement. It makes the check `inconclusive`, the same rule as D39's validation.
  - The claim is "resolvers X and Y gave different answers at times T1 and T2". The finding itself never says that receivers will reject mail; the impact text may say only that receivers using X see the other record.
- **Evidence gap before it can ship.** Under its own guardrail, **the icicibank case would not have fired**: it was gone on retry. The one persistent difference in the run was a harmless TXT string, not an email record. So no persistent real positive is known yet, and the check may rarely fire. Measure how often it fires on a wider pool before building it, so it does not become another D28 (a check that can never fire live).
- **Effort.** S: the multi-resolver routing exists, and the TTL-aware retry is new.

## 4. Protection for parked domains · QUICK WIN

- **What it does.** Across a customer's domain portfolio, it flags domains that send no mail but lack the three records that stop anyone forging mail from them: a null MX (`MX 0 .`, RFC 7505), `v=spf1 -all`, and DMARC `p=reject`. It gives the three records ready to paste.
- **Where it came from.** D47 ([ledger](14-progress-ledger.md#d-deferred-register)). Email live run 2 had 6 domains with no MX or a null MX, and the transport checks were moot on them. The opposite question was never asked: does a domain that receives no mail *say* it sends none?
- **Customer value.** Parked and defensive domains are spoofed precisely because nobody watches them. Three DNS records close the gap, and a portfolio view finds the ones that were forgotten.
- **Guardrails.**
  - "Sends no mail" is never inferred. The customer declares a domain parked, or the domain already publishes a null MX. A domain with no MX may still send mail, so it gets the question, not the finding.
  - On a domain that sends no mail, `p=reject` has no legitimate mail to block. This is the one case where #1's staged rollout does not apply, and the text says why. If the customer is unsure whether anything sends from the domain, #1's staged rollout applies after all.
  - It must fire on a real positive: one of run 2's no-MX domains, checked against the archive, that lacks the records.
- **Effort.** S: the email checks already read all three records. This adds a portfolio roll-up and a record generator.

## 5. Group findings by fix

- **What it does.** It groups findings that one change closes, and says so: "publishing X closes N findings".
- **Where it came from.** The `?all` + `p=none` double count ([ledger, email v1.2.0](14-progress-ledger.md)). The two findings now name each other, but a customer still sees two rows for one fix. The ledger records that `core/correlation.py` only adds derived findings and cannot suppress.
- **Customer value.** Triage by fix rather than by finding. The fix list shrinks to what someone has to do.
- **Guardrails.**
  - A grouping is a claim, so it needs evidence. "X closes N" is shown only when re-running those N checks against the proposed record clears them. The scanner parses the proposed record offline; nothing touches the target.
  - Findings keep their own ids, states and history. Grouping is a view, never a merge, so `scan verify` still closes each one on its own evidence.
  - It is built in `core/correlation.py` (extend, do not rebuild). If it needs suppression, that is a core change with its own ADR.
- **Effort.** M: correlation rules plus the offline re-evaluation.

## 6. Change alerts and fix evidence

- **What it does.** After each scan, it reports what is **new**, **fixed** and **regressed** since the last one. It produces a verified-fixed record for auditors: the finding, the test that proved it, and the re-run that observed it gone.
- **Where it came from.** It builds on what exists: deterministic finding ids, the finding store and `scan verify` ([runbook §2a](12-cli-runbook.md#2a-persistence-and-scan-verify)). **It depends on the read-only store fix** (merged in PR #25, 2026-10-09), because an auditor receives a read-only copy.
- **Customer value.** It answers "did our fix work?" with evidence, and gives an auditor a record they can re-check rather than a screenshot.
- **Guardrails.**
  - **"Fixed" means `scan verify` observed the problem gone**, never that a finding was missing from a scan. A missing finding may mean the check did not run (ADR-022, `core/store.py`).
  - "Regressed" requires a finding that was verified fixed to reappear, and records both observations.
  - The auditor record holds evidence only after redaction (ADR-028), and says "compliance readiness", never "compliant" (ADR-011).
- **Effort.** M: diffing store snapshots and an export format, both reusing what exists.
